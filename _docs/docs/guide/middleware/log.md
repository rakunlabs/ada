# Log

Log middleware is used to log incoming requests and outgoing responses.  
It helps in monitoring and debugging your application by providing insights into the request lifecycle.

Default log uses `slog` to print logs in _debug_ mode.

```go
mlog "github.com/rakunlabs/ada/middleware/log"
```

Add middleware to directly mux, group or handle; usually placed in the top of the middleware chain:

```go
mlog.Middleware()
```

By default, `remote_ip` is the immediate peer from `r.RemoteAddr`. Forwarding
headers such as `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` are ignored
so a direct client cannot spoof the logged address.

When Ada is behind a reverse proxy, list the proxy networks explicitly:

```go
mlog.Middleware(
    mlog.WithTrustedProxies("10.0.0.0/8", "fd00::/8"),
)
```

Only a matching immediate peer may supply forwarding headers. Ensure that the
proxy overwrites incoming forwarding headers rather than appending untrusted
values. `mlog.WithUnsafeProxyHeaders()` restores the old trust-all behavior for
compatibility, but should only be used when an external network boundary is
already enforced.

The same rules apply to the helpers: `mlog.RealIP` ignores forwarding headers,
while `mlog.TrustedRealIP(cidrs...)` returns a helper with an explicit proxy
policy.

Example output:

```sh
2025-11-01 18:35:33 CET DBG log/log.go:101 request user="" route=/ request_id=01K907T8BP43F4S0M30QE37J07 remote_ip=::1 host=localhost:8080 method=GET uri=/ user_agent=Mozilla/5.0 status=200 latency=276713 latency_human=276.713µs bytes_in="" bytes_out=29
```

## Configuration

You can configure the middleware using `mlog.Option` functions.

```go
// skipper example to show skip logging for GET requests
mlog.Middleware(mlog.WithSkipper(func(r *http.Request) bool {
    if r.Method == http.MethodGet {
        return true
    }

    return false
}))
```

This logger also adds `request_id`, `user` and `user_agent` fields to the log context if available.

Use our `logi` package to make context-aware logging in your handlers:

```go
// import "github.com/rakunlabs/logi"
logi.Ctx(r.Context()).Info("saying hello")
```
