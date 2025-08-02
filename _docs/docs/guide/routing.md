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

### Method-Agnostic Routing

You can also register handlers that respond to any HTTP method:

```go
server.HandleFunc("/health", healthCheck)
server.Handle("/static", http.FileServer(http.Dir("./static")))
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
