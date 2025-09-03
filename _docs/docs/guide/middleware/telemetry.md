# Telemetry

Opentelemetry middleware for trace and metrics.

```go
mtelemetry "github.com/rakunlabs/ada/middleware/telemetry"
```

To use telemetry middleware, you need to start and set global tracing and metrics providers.

Use `tell` package for that check (https://github.com/rakunlabs/tell)

To start example must set `service.name` attribute.

```sh
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
export OTEL_RESOURCE_ATTRIBUTES=service.name=my-service
```
