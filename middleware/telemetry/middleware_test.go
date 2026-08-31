package telemetry

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestMiddlewareRecordsConfiguredAndDownstreamAttributes(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = meterProvider.Shutdown(context.Background()) })

	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })

	handler := Middleware(
		WithMeterProvider(meterProvider),
		WithTracerProvider(tracerProvider),
		WithMetricAttributesFn(func(*http.Request) []attribute.KeyValue {
			return []attribute.KeyValue{attribute.String("metric.configured", "yes")}
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		labeler, ok := otelhttp.LabelerFromContext(r.Context())
		if !ok {
			t.Error("handler context has no telemetry labeler")
		} else {
			labeler.Add(attribute.String("handler.added", "yes"))
		}
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodPost, "http://server.example/resource", nil)
	req.URL.Scheme = ""
	req.TLS = &tls.ConnectionState{}
	handler.ServeHTTP(httptest.NewRecorder(), req)

	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	attrs, ok := sumPointAttributes(metrics, "http.server.total_requests")
	if !ok {
		t.Fatal("http.server.total_requests metric was not recorded")
	}
	assertStringAttribute(t, attrs, "metric.configured", "yes")
	assertStringAttribute(t, attrs, "handler.added", "yes")
	assertStringAttribute(t, attrs, "url.scheme", "https")

	spans := spanRecorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}
	spanAttrs := attribute.NewSet(spans[0].Attributes()...)
	assertStringAttribute(t, spanAttrs, "handler.added", "yes")
}

func TestTraceAndMetricSchemeDerivationMatches(t *testing.T) {
	tests := []struct {
		name      string
		urlScheme string
		tls       bool
		want      string
	}{
		{name: "TLS ignores absolute HTTP form", urlScheme: "http", tls: true, want: "https"},
		{name: "TLS ignores attacker scheme", urlScheme: "attacker-controlled", tls: true, want: "https"},
		{name: "TLS fallback", tls: true, want: "https"},
		{name: "plain HTTP ignores absolute HTTPS form", urlScheme: "https", want: "http"},
		{name: "plain HTTP ignores attacker scheme", urlScheme: "attacker-controlled", want: "http"},
		{name: "plain HTTP fallback", want: "http"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://server.example/resource", nil)
			req.URL.Scheme = tt.urlScheme
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			} else {
				req.TLS = nil
			}

			spanAttrs := attribute.NewSet(RequestTraceAttrs(req)...)
			metricAttrs := attribute.NewSet(MetricAttributes(req, http.StatusOK, nil)...)
			assertStringAttribute(t, spanAttrs, "url.scheme", tt.want)
			assertStringAttribute(t, metricAttrs, "url.scheme", tt.want)
		})
	}
}

func TestWithFilterSkipsTelemetryAndCallsNext(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })

	called := false
	handler := Middleware(
		WithTracerProvider(tracerProvider),
		WithFilter(func(r *http.Request) bool { return r.URL.Path != "/health" }),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if !called {
		t.Fatal("filtered request did not reach downstream handler")
	}
	if len(spanRecorder.Ended()) != 0 {
		t.Fatalf("filtered request produced %d spans", len(spanRecorder.Ended()))
	}
}

func TestRequestTraceAttrsUseImmediatePeer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://server.example/resource", nil)
	req.RemoteAddr = "[2001:db8:ffff::3]:443"
	req.Header.Set("X-Forwarded-For", "2001:db8:dead::99, 2001:db8:1234::8, 2001:db8:ffff::2")

	safe := attribute.NewSet(RequestTraceAttrs(req)...)
	assertStringAttribute(t, safe, "client.address", "2001:db8:ffff::3")
}

// client.address follows the injected resolver, while network.peer.address
// stays the immediate peer: the two are different facts and must not merge.
func TestMiddlewareWithClientIPSetsClientAddress(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })

	handler := Middleware(
		WithTracerProvider(tracerProvider),
		WithClientIP(func(r *http.Request) string { return r.Header.Get("X-Real-IP") }),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://server.example/resource", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Real-IP", "198.51.100.8")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := spanRecorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}

	attrs := attribute.NewSet(spans[0].Attributes()...)
	assertStringAttribute(t, attrs, "client.address", "198.51.100.8")
	assertStringAttribute(t, attrs, "network.peer.address", "10.0.0.2")
}

// An empty result must not erase the attribute; falling back to the peer keeps
// client.address always populated.
func TestClientIPResolverFallsBackToPeer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://server.example/resource", nil)
	req.RemoteAddr = "10.0.0.2:443"

	attrs := attribute.NewSet(requestTraceAttrs(req, func(*http.Request) string { return "" })...)
	assertStringAttribute(t, attrs, "client.address", "10.0.0.2")
}

func sumPointAttributes(metrics metricdata.ResourceMetrics, name string) (attribute.Set, bool) {
	for _, scope := range metrics.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok || len(sum.DataPoints) == 0 {
				return attribute.Set{}, false
			}

			return sum.DataPoints[0].Attributes, true
		}
	}

	return attribute.Set{}, false
}

func assertStringAttribute(t *testing.T, attrs attribute.Set, key, want string) {
	t.Helper()
	value, ok := attrs.Value(attribute.Key(key))
	if !ok {
		t.Fatalf("attribute %q is missing from %v", key, attrs.ToSlice())
	}
	if got := value.AsString(); got != want {
		t.Fatalf("attribute %q = %q, want %q", key, got, want)
	}
}
