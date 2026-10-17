# Log

Logs incoming requests and outgoing responses, giving you insight into the request lifecycle for monitoring and debugging.

By default it logs with `slog` at _debug_ level.

## Import

```go
mlog "github.com/rakunlabs/ada/middleware/log"
```

## Usage

Usually placed at the top of the middleware chain, after [Recover](./recover) and [Request ID](./request-id):

```go
server.Use(mlog.Middleware())
```

Example output:

```sh
2025-11-01 18:35:33 CET DBG log/log.go:101 request user="" route=/ request_id=01K907T8BP43F4S0M30QE37J07 remote_ip=::1 host=localhost:8080 method=GET uri=/ user_agent=Mozilla/5.0 status=200 latency=276713 latency_human=276.713µs bytes_in="" bytes_out=29
```

The logger also adds `request_id`, `user`, and `user_agent` fields to the log context when they are available.

## Options

| Option | Default | Description |
|---|---|---|
| `WithLogger(Logger)` | `slog`-based | Replace the logger |
| `WithSkipper(func(*http.Request) bool)` | `nil` | Return `true` to skip logging a request |
| `WithRealIP(func(*http.Request) string)` | `mlog.RealIP` | How `remote_ip` is derived. See [Client Address](#client-address) |
| `WithPreFunc(func(*http.Request) *http.Request)` | adds context fields | Runs before the handler |
| `WithPostFunc(func(*http.Request, *Response))` | writes the log line | Runs after the handler |

```go
// Skip logging for GET requests
mlog.Middleware(mlog.WithSkipper(func(r *http.Request) bool {
    return r.Method == http.MethodGet
}))
```

## Client Address

By default, `remote_ip` is the immediate peer from `r.RemoteAddr`. Forwarding
headers such as `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` are ignored
so a direct client cannot spoof the logged address.

This package holds no proxy policy of its own, and depends on nothing beyond
the standard library and its logger. Resolving `X-Forwarded-For` correctly
requires knowing where the trust boundary sits, which is a deployment fact
rather than a logging one, so it is injected instead:

```go
import "github.com/rakunlabs/ada/middleware/auth/proxy"

mlog.Middleware(
    mlog.WithRealIP(proxy.TrustedRealIP("10.0.0.0/8", "fd00::/8")),
)
```

Only a matching immediate peer may supply forwarding headers. Ensure that the
proxy overwrites incoming forwarding headers rather than appending untrusted
values.

::: warning
`proxy.UnsafeRealIP` restores the trust-all behavior, but should only be
used when an external network boundary is already enforced.
:::

`WithRealIP` takes any `func(*http.Request) string`, so a deployment that
derives the client address some other way can supply its own. `mlog.RealIP` is
the default and ignores forwarding headers.

## Logging in Handlers

Use the [`logi`](https://github.com/rakunlabs/logi) package for context-aware logging in your handlers:

```go
// import "github.com/rakunlabs/logi"
logi.Ctx(r.Context()).Info("saying hello")
```
