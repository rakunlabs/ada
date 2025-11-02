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

Example output:

```sh
2025-11-01 18:35:33 CET DBG log/log.go:101 request user="" route=/ request_id=01K907T8BP43F4S0M30QE37J07 remote_ip=[::1]:34186 host=localhost:8080 method=GET uri=/ user_agent=Mozilla/5.0 status=200 latency=276713 latency_human=276.713µs bytes_in="" bytes_out=29
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
