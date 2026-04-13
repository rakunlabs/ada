# Routing

Ada provides a flexible HTTP routing system that supports static routes, parameterized routes, and wildcard matching.

The routing system doesn't use http Method, so you can use any method you want.

## Route Patterns

Routing system follows a specific priority order when matching routes:

1. **Static routes** - Exact matches have highest priority
2. **Parameterized routes** - Routes with path parameters
3. **Wildcard routes** - Routes with `*` wildcards

```go
server.GET("/users/new", newUserForm)      // Highest priority
server.GET("/users/{id}", getUser)         // Medium priority
server.GET("/users/*", catchAllUsers)      // Lowest priority
```

A request to `/users/new` will match the static route, not the parameterized route.

### Static Routes

Static routes match exact path segments:

```go
server.GET("/", homeHandler)
server.GET("/about", aboutHandler)
server.GET("/api/v1/status", statusHandler)
```

### Parameterized Routes

Parameterized routes capture path segments and make them available via `r.PathValue()`:

```go
server.GET("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
    userID := r.PathValue("id")
    fmt.Fprintf(w, "User ID: %s", userID)
})

server.GET("/posts/{postID}/comments/{commentID}", func(w http.ResponseWriter, r *http.Request) {
    postID := r.PathValue("postID")
    commentID := r.PathValue("commentID")
    fmt.Fprintf(w, "Post: %s, Comment: %s", postID, commentID)
})
```

### Wildcard Routes

Wildcard routes use `*` to match any segment at that position:

```go
server.GET("/files/*", func(w http.ResponseWriter, r *http.Request) {
    // requestedPath := r.PathValue("*") // "/files/anything/1881" -> "anything/1881"
    // Matches /files/anything, /files/path/to/file, etc.
    fmt.Fprintf(w, "File path requested")
})
```


## Route Groups

Route groups allow you to organize routes with common prefixes and middleware:

```go
server := ada.New()

// Create an API v1 group
apiV1 := server.Group("/api/v1")
apiV1.GET("/users", getUsers)
apiV1.POST("/users", createUser)
apiV1.DELETE("/users/{id}", deleteUser)

// Create an admin group with audit middleware
admin := server.Group("/admin", auditMiddleware)
admin.GET("/dashboard", adminDashboard)
admin.GET("/users", adminUsers)
admin.POST("/users/{id}/ban", banUser)
```

Groups can be nested for more complex organization:

```go
api := server.Group("/api")
v1 := api.Group("/v1")
v1.GET("/users", getUsersV1)

v2 := api.Group("/v2")
v2.GET("/users", getUsersV2)
```

## HTTP Methods

Ada supports all standard HTTP methods through dedicated methods:

```go
server := ada.New()

server.GET("/users", getUsers)
server.POST("/users", createUser)
server.PUT("/users/{id}", updateUser)
server.PATCH("/users/{id}", patchUser)
server.DELETE("/users/{id}", deleteUser)
server.HEAD("/users/{id}", headUser)
server.OPTIONS("/users", optionsUsers)
server.TRACE("/trace", traceHandler)
server.CONNECT("/connect", connectHandler)
```

Other not standard HTTP methods can be added with `HandleWithMethod`

```go
server.HandleWithMethod("FOO", "/foo", fooHandler)
```

### Method-Agnostic Routing

You can also register handlers that respond to any HTTP method:

```go
server.HandleFunc("/health", healthCheck)
server.Handle("/static", http.FileServer(http.Dir("./static")))
```

## Automatic HEAD and OPTIONS

Ada automatically handles HEAD and OPTIONS requests:

- **HEAD**: If a GET handler is registered, HEAD requests are served by the same handler. Go's `http.ResponseWriter` automatically suppresses the response body. Explicit HEAD handlers take priority.
- **OPTIONS**: Returns `204 No Content` with an `Allow` header listing available methods (e.g. `Allow: GET, HEAD, OPTIONS, POST`). Explicit OPTIONS handlers take priority.

## 405 Method Not Allowed

When a request matches a path but not any registered method, Ada returns `405 Method Not Allowed` with an `Allow` header listing the available methods:

```
GET /users         → 200 OK
POST /users        → 405 Method Not Allowed (Allow: GET, HEAD, OPTIONS)
GET /nonexistent   → 404 Not Found
```

## Custom 404 Handler

You can set a custom handler for routes that don't match:

```go
server := ada.New()
server.NotFound(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusNotFound)
    fmt.Fprintf(w, "Page not found: %s", r.URL.Path)
})
```

## Custom 405 Handler

You can set a custom handler for method-not-allowed responses. The `Allow` header is always set before the handler is called:

```go
server := ada.New()
server.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusMethodNotAllowed)
    w.Write([]byte(`{"error":"method not allowed","allow":"` + w.Header().Get("Allow") + `"}`))
})
```
