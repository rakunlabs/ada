# Server

Adds the [`Server`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Server) HTTP header to every response, identifying the server software.

## Import

```go
mserver "github.com/rakunlabs/ada/middleware/server"
```

## Usage

Usually placed at the top of the middleware chain:

```go
server.Use(mserver.Middleware("my-server/v1.2.3"))
```

`Middleware` takes the header value as its only argument; there are no other options.

::: warning
Identifying the server software helps with debugging, analytics, and compliance, but it also tells attackers what you run. Prefer a product name over an exact version on public endpoints.
:::
