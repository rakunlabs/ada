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

## Trusted Proxies

Telemetry records the immediate peer as `client.address` by default and ignores
`X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP`. This prevents clients
from choosing their own trace identity and metric dimensions.

Behind a reverse proxy, configure the CIDRs of the immediate proxies:

```go
mux.Use(mtelemetry.Middleware(
    mtelemetry.WithTrustedProxies("10.0.0.0/8", "fd00::/8"),
))
```

`network.peer.address` still describes the direct connection;
`client.address` is derived from forwarding headers only when that direct peer
is trusted. `mtelemetry.WithUnsafeProxyHeaders()` restores the legacy
trust-all behavior and is intended only as a temporary compatibility option.

For custom instrumentation, `RequestTraceAttrs` also ignores forwarding
headers. Use `TrustedRequestTraceAttrs(cidrs...)` when the same explicit proxy
policy is required.
