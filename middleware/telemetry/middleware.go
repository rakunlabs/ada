package telemetry

import (
	"net/http"
	"time"

	"github.com/felixge/httpsnoop"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/semconv/v1.34.0/httpconv"
	"go.opentelemetry.io/otel/trace"
)

const (
	// ScopeName is the instrumentation scope name.
	ScopeName = "github.com/rakunlabs/ada/middleware/telemetry"
)

// Middleware is an echo middleware to add metrics to rec for each HTTP request.
// If recorder config is nil, the middleware will use a recorder with default configuration.
func Middleware(opts ...Option) func(next http.Handler) http.Handler {
	cfg := config{}
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.TracerProvider == nil {
		cfg.TracerProvider = otel.GetTracerProvider()
	}
	tracer := cfg.TracerProvider.Tracer(
		ScopeName,
		trace.WithInstrumentationVersion(Version()),
	)
	if cfg.Propagators == nil {
		cfg.Propagators = otel.GetTextMapPropagator()
	}
	if cfg.SpanNameFormatter == nil {
		cfg.SpanNameFormatter = spanNameFormatter
	}
	if cfg.MeterProvider == nil {
		cfg.MeterProvider = otel.GetMeterProvider()
	}
	metricMeter := cfg.MeterProvider.Meter(
		ScopeName,
		metric.WithInstrumentationVersion(Version()),
	)

	meter := NewHTTPMeter(metricMeter)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, filter := range cfg.Filters {
				if !filter(r) {
					next.ServeHTTP(w, r)

					return
				}
			}

			requestStartTime := time.Now()

			ctx := r.Context()

			ctx = cfg.Propagators.Extract(ctx, propagation.HeaderCarrier(r.Header))
			opts := []trace.SpanStartOption{
				trace.WithAttributes(RequestTraceAttrs(r)...),
				trace.WithSpanKind(trace.SpanKindServer),
			}

			if cfg.PublicEndpoint || (cfg.PublicEndpointFn != nil && cfg.PublicEndpointFn(r.WithContext(ctx))) {
				opts = append(opts, trace.WithNewRoot())
				// Linking incoming span context if any for public endpoint.
				if s := trace.SpanContextFromContext(ctx); s.IsValid() && s.IsRemote() {
					opts = append(opts, trace.WithLinks(trace.Link{SpanContext: s}))
				}
			}

			routeStr := extractRoute(r)
			opts = append(opts, trace.WithAttributes(routeAttr(routeStr)))
			ctx, span := tracer.Start(ctx, cfg.SpanNameFormatter(routeStr, r), opts...)
			defer span.End()

			bw := NewBodyWrapper(r.Body)
			if r.Body != nil && r.Body != http.NoBody {
				r.Body = bw
			}

			labeler, found := otelhttp.LabelerFromContext(ctx)
			if !found {
				ctx = otelhttp.ContextWithLabeler(ctx, labeler)
			}

			labelerAttrs := labeler.Get()

			meter.requestActive.Add(ctx, 1, httpconv.RequestMethodAttr(r.Method), r.URL.Scheme, labelerAttrs...)
			defer meter.requestActive.Add(ctx, -1, httpconv.RequestMethodAttr(r.Method), r.URL.Scheme, labelerAttrs...)

			m := httpsnoop.CaptureMetrics(next, w, r.WithContext(ctx))

			span.SetStatus(metricStatus(m.Code))
			span.SetAttributes(ResponseTraceAttrs(ResponseTelemetry{
				StatusCode: m.Code,
				ReadBytes:  bw.BytesRead(),
				WriteBytes: m.Written,
			})...)
			span.SetAttributes(labelerAttrs...)

			meter.Record(ctx, MetricData{
				Request:              r,
				RequestSize:          bw.BytesRead(),
				ResponseSize:         m.Written,
				ElapsedTime:          float64(time.Since(requestStartTime)) / float64(time.Millisecond),
				StatusCode:           m.Code,
				AdditionalAttributes: labelerAttrs,
			})
		})
	}
}
