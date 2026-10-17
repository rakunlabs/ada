# Request ID

Assigns a unique identifier to each request. Use it to correlate logs and trace a request across services.

## Import

```go
mrequestid "github.com/rakunlabs/ada/middleware/requestid"
```

## Usage

Usually placed at the top of the middleware chain:

```go
server.Use(mrequestid.Middleware())
```

If the incoming request already has an `X-Request-Id` header, that value is kept. Otherwise a new ID is generated and set on the request. The ID is also echoed back in the `X-Request-Id` response header.

::: tip
Place it before [Log](./log) so every log line carries the `request_id` field.
:::

## Options

| Option | Default | Description |
|---|---|---|
| `WithGenerateRequestID(func() string)` | [ULID](https://github.com/oklog/ulid) | Function that generates a new request ID |

```go
mrequestid.Middleware(
    mrequestid.WithGenerateRequestID(func() string {
        return myCustomIDGenerator()
    }),
)
```
