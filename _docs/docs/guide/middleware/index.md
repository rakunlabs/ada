# Middleware

Middleware provides a way to execute code before and after HTTP requests.

## Overview

Middleware functions follow the standard Go HTTP middleware pattern:

```go
func(next http.Handler) http.Handler
```

They can be chained together and applied globally to all routes or to specific route groups.

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

> Middleware added with `Use` only affects handlers and groups registered after the call; it does not apply to routes or groups defined earlier.

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
