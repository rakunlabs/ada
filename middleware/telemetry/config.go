package telemetry

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

type config struct {
	MeterProvider  metric.MeterProvider
	TracerProvider trace.TracerProvider
	Propagators    propagation.TextMapPropagator
	Filters        []Filter

	PublicEndpoint   bool
	PublicEndpointFn func(*http.Request) bool

	SpanNameFormatter  func(routeName string, r *http.Request) string
	MetricAttributesFn func(*http.Request) []attribute.KeyValue
}

// Filter is a predicate used to determine whether a given http.request should be traced.
// A Filter must return true if the request should be traced.
type Filter func(*http.Request) bool

type Option func(*config)

// WithMeterProvider specifies a meter provider to use for creating a metric.
// If none is specified, the global provider is used.
func WithMeterProvider(provider metric.MeterProvider) Option {
	return func(o *config) {
		o.MeterProvider = provider
	}
}

// WithTracerProvider specifies a tracer provider to use for creating spans.
// If none is specified, the global provider is used.
func WithTracerProvider(provider trace.TracerProvider) Option {
	return func(o *config) {
		o.TracerProvider = provider
	}
}

// WithPropagators specifies propagators to use for extracting information from the HTTP requests.
// If none are specified, global ones will be used.
func WithPropagators(propagators propagation.TextMapPropagator) Option {
	return func(o *config) {
		if propagators != nil {
			o.Propagators = propagators
		}
	}
}

// WithSpanNameFormatter specifies a span name formatter to use for creating span names.
func WithSpanNameFormatter(formatter func(routeName string, r *http.Request) string) Option {
	return func(o *config) {
		o.SpanNameFormatter = formatter
	}
}

// WithPublicEndpoint configures the Handler to link the span with an incoming
// span context. If this option is not provided, then the association is a child
// association instead of a link.
func WithPublicEndpoint() Option {
	return func(o *config) {
		o.PublicEndpoint = true
	}
}

// WithPublicEndpointFn runs with every request, and allows conditionally
// configuring the Handler to link the span with an incoming span context. If
// this option is not provided or returns false, then the association is a
// child association instead of a link.
// Note: WithPublicEndpoint takes precedence over WithPublicEndpointFn.
func WithPublicEndpointFn(fn func(*http.Request) bool) Option {
	return func(o *config) {
		o.PublicEndpointFn = fn
	}
}

// WithMetricAttributesFn allows customizing the attributes added to metrics.
func WithMetricAttributesFn(fn func(*http.Request) []attribute.KeyValue) Option {
	return func(o *config) {
		o.MetricAttributesFn = fn
	}
}
