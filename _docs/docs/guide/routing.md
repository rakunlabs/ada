# Routing

Ada provides a flexible HTTP routing system that supports static routes, parameterized routes, and wildcard matching.

The routing system doesn't use http Method, so you can use any method you want.

## Route Patterns

Within a single path segment, the router prefers the most specific alternative:

1. **Static routes** - Exact matches are tried first
2. **Parameterized routes** - Routes with path parameters
3. **Wildcard routes** - Routes with `*` or `{name...}` captures

```go
server.GET("/users/new", newUserForm)      // tried first
server.GET("/users/{id}", getUser)         // then this
server.GET("/users/*", catchAllUsers)      // then this
```

A request to `/users/new` matches the static route, not the parameterized one.

### How a path is matched

The ordering is a preference, not an irrevocable choice. The router follows the
most specific branch first. If that branch fails at a later segment, it
backtracks to the nearest untried parameterized or wildcard alternative:

```go
server.GET("/foo/bar", handlerA)
server.GET("/{x}/baz", handlerB)

// GET /foo/bar  -> handlerA
// GET /foo/baz  -> handlerB with x = "foo"
```

This also lets a static alias coexist with a parameterized subtree:

```go
server.GET("/users/me", currentUser)
server.GET("/users/{id}/posts", userPosts)

// GET /users/me        -> currentUser
// GET /users/42/posts  -> userPosts, id = "42"
// GET /users/me/posts  -> userPosts, id = "me"
```

The result does not depend on registration order. A trailing `*` or
`{name...}` is also remembered as a fallback while more specific branches are
tried, which makes SPA and proxy catch-alls work as expected.

### Static Routes

Static routes match exact path segments:

```go
server.GET("/", homeHandler)
server.GET("/about", aboutHandler)
server.GET("/api/v1/status", statusHandler)
```

### Parameterized Routes

Parameterized routes capture a **single** path segment and make it available via `r.PathValue()`:

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

`{name}` matches exactly one segment. It does **not** cross `/` boundaries — use the greedy `{name...}` form below when you need that.

### Wildcard Routes

Ada has two wildcard forms:

| Form        | Position       | Matches                                                               | Access via            |
| ----------- | -------------- | --------------------------------------------------------------------- | --------------------- |
| `*`         | Middle or trailing (1 per route) | A non-empty descendant: one segment if middle, the rest if trailing   | `r.PathValue("*")`    |
| `{name...}` | Trailing only  | A non-empty descendant: the rest of the path (including `/`)          | `r.PathValue("name")` |

`{name...}` is just a **named alias** for a trailing `*` — same matching, only the `PathValue` key differs. Use it when a descriptive name reads better than `"*"`, especially in routes that already have another capture.

```go
// Trailing `*` — anonymous greedy capture.
server.GET("/files/*", func(w http.ResponseWriter, r *http.Request) {
    rest := r.PathValue("*")
    // GET /files/a/b/c.txt → rest == "a/b/c.txt"
})

// Middle `*` — exactly one segment, does not cross `/`.
server.POST("/api/v1/external/*/test", func(w http.ResponseWriter, r *http.Request) {
    name := r.PathValue("*")
    // POST /api/v1/external/myname/test → name == "myname"
    // POST /api/v1/external/a/b/test    → 404
})

// Trailing `{name...}` — named greedy capture.
server.GET("/files/{path...}", func(w http.ResponseWriter, r *http.Request) {
    path := r.PathValue("path")
    // GET /files/a/b/c.txt → path == "a/b/c.txt"
    // GET /files/          → 404 (empty descendants do not match)
    // GET /files           → 404 (separator required)
})
```

`HandleFuncWildcard` and `HandleWildcard` add the trailing wildcard for you,
but they remain descendant-only. Passing `"/assets"` registers
`"/assets/*"`; neither `"/assets"` nor `"/assets/"` matches it. Add a separate
exact handler when the base path should also resolve:

```go
server.HandleFunc("/assets", assetsHandler)         // exact base path
server.HandleFuncWildcard("/assets", assetsHandler) // non-empty descendants
```

#### Combining captures

Stack any number of `{name}` params; the wildcard rules only apply to `*` and `{name...}`. Each capture lives under its own key.

```go
// Middle `{name}` + named greedy trailing.
server.GET("/users/{name}/files/{path...}", func(w http.ResponseWriter, r *http.Request) {
    name := r.PathValue("name") // e.g. "alice"
    path := r.PathValue("path") // e.g. "docs/note.md"
})

// Multiple single-segment params + greedy trailing.
server.GET("/orgs/{org}/users/{user}/files/{path...}", h)
```

#### Validation rules

Ada panics at registration time on ambiguous patterns — bad routes fail loud at boot:

1. **At most one `*` per route.** Both would map to `PathValue("*")`. Use `{name}` for the other capture.
2. **At most one `{name...}`, and it must be trailing.** A greedy match consumes the rest of the path by definition, so it can't sit in the middle (the matcher would have nothing to stop against) and can't appear twice (the first one already ate everything).

```go
server.GET("/a/*/b/*", h)        // panics: more than one '*'
server.GET("/a/{x...}/b", h)     // panics: greedy must be trailing
```

## Path Handling And Captured Values {#path-handling}

::: danger Captured values are attacker-controlled
Ada matches on the **decoded** `r.URL.Path` exactly as received. It does **not**
run `path.Clean` and it does **not** redirect, unlike `net/http.ServeMux`.
Every value returned by `r.PathValue` — and greedy captures especially — is raw
attacker input. **Validate or clean it before using it as a filesystem path, a
key, a redirect target, or anything else with authority.**
:::

`net/http.ServeMux` cleans the request path and answers with a `301` to the
canonical form. Ada deliberately does neither: the path you registered is the
path that is matched, so proxies, signed URLs, and pass-through handlers see
byte-identical paths. The cost is that normalisation is your responsibility.

### Traversal segments reach your handler

`.` and `..` are ordinary path characters to the router. They are not resolved,
not rejected, and — because `r.URL.Path` is already percent-decoded — an encoded
`..%2f` is indistinguishable from a literal `../` by the time matching happens:

```go
server.GET("/static/{path...}", func(w http.ResponseWriter, r *http.Request) {
    p := r.PathValue("path")
    // GET /static/../../etc/passwd      → p == "../../etc/passwd"
    // GET /static/..%2f..%2fetc/passwd  → p == "../../etc/passwd"
})
```

Both requests reach the handler with a `200`. Handing `p` to `os.Open`,
`filepath.Join`, or `http.ServeFile` without checking is a directory traversal.

Clean and confine the value before it touches the filesystem:

```go
server.GET("/static/{path...}", func(w http.ResponseWriter, r *http.Request) {
    // Anchor at "/" so ".." can never climb above the root, then trim it.
    clean := strings.TrimPrefix(path.Clean("/"+r.PathValue("path")), "/")

    f, err := root.Open(clean) // root is an *os.Root or fs.FS
    if err != nil {
        http.NotFound(w, r)
        return
    }
    defer f.Close()
    // ...
})
```

Prefer `os.OpenRoot` (Go 1.24+) or an `fs.FS` rooted at the directory you intend
to serve: they enforce the boundary in the kernel/VFS layer instead of relying on
string hygiene. Ada's own [`handler/folder`](./handler/folder) already does
this — reach for it before hand-rolling a file server.

### `%2F` cannot be captured by a `{name}` param

Because matching runs on the decoded path, a percent-encoded slash becomes a
real separator before the router sees it. A single-segment param can therefore
**never** contain a `/`, encoded or not:

```go
server.GET("/users/{id}", getUser)

// GET /users/a%2Fb  → decoded to /users/a/b → 404, not id == "a/b"
```

If an identifier can legitimately contain `/`, do not put it in a path segment.
Use a query parameter, a request body, or an encoding without `/` (base64url,
hex) instead. The same applies to `%2E%2E`, which decodes to `..` and is matched
as such.

Note also that empty segments are preserved: `/users//a` is not folded to
`/users/a` and will 404 against `/users/{id}`.

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
server.QUERY("/search", searchHandler)
```

The `QUERY` method is a safe and idempotent HTTP method that carries the query in the request body ([RFC 10008 - The HTTP QUERY Method](https://www.rfc-editor.org/rfc/rfc10008.html)). Since `net/http` does not define a constant for it yet, ada exposes `ada.MethodQuery`.

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
