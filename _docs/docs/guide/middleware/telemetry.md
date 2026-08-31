# Telemetry

OpenTelemetry middleware for HTTP server traces and metrics.

```go
mtelemetry "github.com/rakunlabs/ada/middleware/telemetry"
```

To use telemetry middleware, start and set global tracing and metrics providers,
then register the middleware:

```go
mux.Use(mtelemetry.Middleware())
```

Use `tell` package for that check (https://github.com/rakunlabs/tell)

To start example must set `service.name` attribute.

```sh
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
export OTEL_RESOURCE_ATTRIBUTES=service.name=my-service
```

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
