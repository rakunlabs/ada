# Telemetry

OpenTelemetry middleware for HTTP server traces and metrics.

## Import

```go
mtelemetry "github.com/rakunlabs/ada/middleware/telemetry"
```

## Usage

Set up the global tracer and meter providers first, then register the middleware:

```go
server.Use(mtelemetry.Middleware())
```

The [`tell`](https://github.com/rakunlabs/tell) package can set up the providers for you. The exporter is configured with the standard OpenTelemetry environment variables, and `service.name` must be set:

```sh
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
export OTEL_RESOURCE_ATTRIBUTES=service.name=my-service
```

## Options

| Option | Default | Description |
|---|---|---|
| `WithTracerProvider(trace.TracerProvider)` | global | Provider used to create spans |
| `WithMeterProvider(metric.MeterProvider)` | global | Provider used to create metrics |
| `WithPropagators(propagation.TextMapPropagator)` | global | Propagators used to extract context from requests |
| `WithFilter(Filter)` | none | Add a filter; all filters must return `true` for a request to be recorded |
| `WithSpanNameFormatter(func(routeName string, r *http.Request) string)` | `METHOD route` | Customize span names |
| `WithPublicEndpoint()` | off | Link incoming span contexts instead of using them as the parent |
| `WithPublicEndpointFn(func(*http.Request) bool)` | `nil` | Per-request version of `WithPublicEndpoint` (which takes precedence) |
| `WithMetricAttributesFn(func(*http.Request) []attribute.KeyValue)` | `nil` | Extra metric attributes |
| `WithClientIP(func(*http.Request) string)` | immediate peer | How `client.address` is derived. See [Client Address](#client-address) |

## Client Address

Telemetry records the immediate peer as `client.address` by default and ignores
`X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP`. This prevents clients
from choosing their own trace identity and metric dimensions.

This package carries no proxy policy of its own, and depends on nothing beyond
OpenTelemetry. Behind a reverse proxy, pass a resolver that knows the trust
boundary:

```go
import "github.com/rakunlabs/ada/middleware/auth/proxy"

mux.Use(mtelemetry.Middleware(
    mtelemetry.WithClientIP(proxy.TrustedRealIP("10.0.0.0/8", "fd00::/8")),
))
```

`network.peer.address` still describes the direct connection; only
`client.address` follows the resolver. The two are different facts and are
never merged. `proxy.UnsafeRealIP` restores the trust-all behavior and is
intended only for deployments with a separately enforced network boundary.

`WithClientIP` accepts any `func(*http.Request) string`. An empty result falls
back to the immediate peer, so `client.address` is always populated.

For custom instrumentation, `RequestTraceAttrs` uses the immediate peer and
ignores forwarding headers.
