# Middleware

Middleware provides a way to execute code before and after HTTP requests.

## Overview

Middleware functions follow the standard Go HTTP middleware pattern:

```go
func(next http.Handler) http.Handler
```

They can be chained together and applied globally to all routes or to specific route groups.

## Registering Middleware

Every middleware in this guide can be added at three levels: the mux, a group, or a single route.

```go
server.Use(mrecover.Middleware())                    // mux: every route registered after this call
api := server.Group("/api", mrequestid.Middleware()) // group: routes under /api
api.GET("/users", handler, timeout.Middleware(5*time.Second)) // single route
```

Cross-cutting middlewares such as [Recover](./recover), [Request ID](./request-id), [Log](./log), and [CORS](./cors) usually sit at the top of the chain on the mux.

## Bundled Middleware

| Middleware | Package | Purpose |
|---|---|---|
| [Recover](./recover) | `middleware/recover` | Recover from panics and answer with a safe 500 |
| [Request ID](./request-id) | `middleware/requestid` | Assign an `X-Request-Id` to every request |
| [Log](./log) | `middleware/log` | Log requests and responses with `slog` |
| [Rate Limit](./ratelimit) | `middleware/ratelimit` | Limit traffic globally, per IP, or per key |
| [Body Limit](./bodylimit) | `middleware/bodylimit` | Cap request body size |
| [Timeout](./timeout) | `middleware/timeout` | Attach a deadline to the request context |
| [CORS](./cors) | `middleware/cors` | Handle cross-origin requests |
| [CSRF](./csrf) | `middleware/csrf` | Reject cross-site unsafe requests, with an optional token check |
| [Telemetry](./telemetry) | `middleware/telemetry` | OpenTelemetry traces and metrics |
| [Encoding](./encoding) | `middleware/encoding` | zstd, Brotli, and gzip response compression |
| [Server](./server) | `middleware/server` | Set the `Server` response header |
| [ForwardAuth](./forwardauth) | `middleware/forwardauth` | Delegate authentication to an external service |
| [Auth](./auth/) | `middleware/auth` | Sessions, login strategies, MFA, and a login UI |

## Middleware Order

The order of middleware matters. Middleware is executed in the order they are added:

1. **Global middleware** (added via `mux.Use()`) is executed first
2. **Group middleware** is executed next
3. **Route-specific middleware** is executed last
4. **Your handler** is executed at the end

```go
mux.Use(middleware1, middleware2)           // Global: 1, 2
api := mux.Group("/api", middleware3)       // Group: 1, 2, 3
api.GET("/users", handler, middleware4)     // Route: 1, 2, 3, 4, handler
```

::: info
Middleware added with `Use` only affects handlers and groups registered after the call; it does not apply to routes or groups defined earlier.
:::

## Runtime Reload

Ada supports replacing, disabling, and adding middlewares at runtime without restarting the server. See the [Runtime Reload](../runtime-reload) guide for details on `Slot` and `Pipeline`.

```go
// Single toggleable middleware
auth := ada.NewSlot(forwardauth.Middleware(...))
server.Use(auth.Middleware())

// Replace at runtime
auth.Replace(forwardauth.Middleware(newOpts...))
auth.Disable()
auth.Enable()
```

## Creating Custom Middleware

You can create your own middleware functions following the standard pattern:

```go
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Check authentication
        token := r.Header.Get("Authorization")
        if token == "" {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        
        // Validate token (implement your logic here)
        if !isValidToken(token) {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
        
        // Call the next handler
        next.ServeHTTP(w, r)
    })
}

func rateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Implement rate limiting logic
        if isRateLimited(r) {
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```
