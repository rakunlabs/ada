# ForwardAuth

ForwardAuth middleware delegates authentication to an external service.  
It forwards the original request headers to an auth service and allows or denies the request based on the response.

```go
mforwardauth "github.com/rakunlabs/ada/middleware/forwardauth"
```

Add middleware to directly mux, group or handler:

```go
mforwardauth.Middleware(
    mforwardauth.WithAddress("http://auth-service:9000/verify"),
)
```

## How It Works

```
Client --> [Middleware] --> [Auth Service]  (headers only, no body)
                                |
                       +--------+--------+
                       |                 |
                  2xx response     non-2xx response
                       |                 |
                 Copy configured    Return auth response
                 response headers   to client (or redirect
                 to original        on GET/HEAD for 401)
                 request, call
                 next handler
```

1. Client sends a request to your application
2. The middleware forwards the request headers (plus `X-Forwarded-*` headers) to the auth service
3. The auth service responds:
   - **2xx**: Authentication succeeded. Configured response headers are copied onto the original request, then the next handler is called
   - **Non-2xx**: Authentication failed. The auth service response (status + body) is returned to the client. For GET/HEAD requests, a redirect to a login page can be configured instead

::: info
The request body is **never** sent to the auth service. Only headers are forwarded.
:::

## Configuration

You can configure the middleware using `mforwardauth.WithConfig()` option or individual `With*` functions.

```go
mforwardauth.Middleware(
    mforwardauth.WithConfig(mforwardauth.ForwardAuth{
        Address:             "https://auth.example.com/verify",
        AuthResponseHeaders: []string{"X-Forwarded-User", "X-Auth-Token"},
        TrustForwardHeader:  true,
        Timeout:             10 * time.Second,
    }),
)
```

Or using individual options:

```go
mforwardauth.Middleware(
    mforwardauth.WithAddress("https://auth.example.com/verify"),
    mforwardauth.WithAuthResponseHeaders("X-Forwarded-User", "X-Auth-Token"),
    mforwardauth.WithTrustForwardHeader(true),
    mforwardauth.WithTimeout(10 * time.Second),
)
```

## Configuration Options

### Address

The URL of the external authentication service. This is the endpoint that receives the forwarded headers and returns an authentication decision.

- **Type:** `string`
- **Required**

```go
mforwardauth.WithAddress("http://auth-service:9000/verify")
```

### AuthResponseHeaders

List of headers to copy from the auth service response onto the original request before forwarding to the backend. This is how the auth service can pass identity information (like username, roles) to downstream handlers.

- **Type:** `[]string`
- **Default:** `[]` (no headers copied)

```go
mforwardauth.WithAuthResponseHeaders("X-Forwarded-User", "X-Auth-Token", "X-Auth-Roles")
```

### AuthResponseHeadersRegex

A regex pattern to match auth response headers to copy onto the original request. Useful when the auth service returns dynamic header names.

- **Type:** `string`
- **Default:** `""` (disabled)

```go
mforwardauth.WithConfig(mforwardauth.ForwardAuth{
    Address:                  "http://auth:9000/verify",
    AuthResponseHeadersRegex: "^X-Auth-.*",
})
```

### AuthRequestHeaders

An allowlist of headers from the original request to forward to the auth service. If empty, all headers are forwarded (except hop-by-hop headers like `Connection`, `Keep-Alive`, etc.).

- **Type:** `[]string`
- **Default:** `[]` (forward all)

```go
// Only forward Authorization and Cookie headers to auth service
mforwardauth.WithAuthRequestHeaders("Authorization", "Cookie")
```

### RequestMethod

The HTTP method to use when calling the auth service.

- **Type:** `string`
- **Default:** `"GET"`

```go
mforwardauth.WithRequestMethod("POST")
```

### TrustForwardHeader

When true, reuses existing `X-Forwarded-*` headers from the original request instead of overwriting them. Enable this when the middleware runs behind another proxy that already sets these headers.

- **Type:** `bool`
- **Default:** `false`

```go
mforwardauth.WithTrustForwardHeader(true)
```

### InsecureSkipVerify

Skips TLS certificate verification when calling the auth service. Only use in development.

- **Type:** `bool`
- **Default:** `false`

```go
mforwardauth.WithInsecureSkipVerify(true)
```

::: warning
Do not enable this in production. It makes the connection to the auth service vulnerable to man-in-the-middle attacks.
:::

### Timeout

Maximum duration to wait for the auth service response. If the auth service does not respond within this duration, the middleware returns `502 Bad Gateway`.

- **Type:** `time.Duration`
- **Default:** `30s`

```go
mforwardauth.WithTimeout(10 * time.Second)
```

### RedirectURL

URL to redirect the client to when the auth service returns a non-2xx response on a **GET or HEAD** request. Non-GET/HEAD requests (POST, PUT, DELETE, etc.) always receive the auth response directly.

Supports the following placeholders which are replaced with URL-encoded values:

| Placeholder | Description | Example Value |
|---|---|---|
| `{url}` | Full original request URL | `https://app.example.com/dashboard?tab=1` |
| `{uri}` | Request URI only (path + query string) | `/dashboard?tab=1` |
| `{host}` | Request host (with port if present) | `app.example.com` |

- **Type:** `string`
- **Default:** `""` (disabled, auth response is returned as-is)

```go
// Redirect with full URL
mforwardauth.WithRedirectURL("https://login.example.com?rd={url}")

// Redirect with path + query only (without scheme and host)
mforwardauth.WithRedirectURL("https://login.example.com?rd={uri}")

// Redirect with path + query and host separately
mforwardauth.WithRedirectURL("https://login.example.com?rd={uri}&host={host}")
```

For example, a user hitting `GET https://app.example.com/dashboard` that gets a 401 from the auth service would be redirected to:

```
# Using {url}
https://login.example.com?rd=https%3A%2F%2Fapp.example.com%2Fdashboard

# Using {uri}
https://login.example.com?rd=%2Fdashboard

# Using {uri} and {host}
https://login.example.com?rd=%2Fdashboard&host=app.example.com
```

::: info
Redirects only apply to **GET** and **HEAD** requests. For other methods (POST, PUT, DELETE, etc.), the auth response is always returned directly to the client. Redirecting a POST to a login page would lose the request body and doesn't make sense.
:::

### RedirectCode

The HTTP status code to use for the redirect.

- **Type:** `int`
- **Default:** `302` (Found)

```go
mforwardauth.WithRedirectCode(http.StatusTemporaryRedirect) // 307
```

### RedirectStatusCodes

List of auth response status codes that trigger a redirect on GET/HEAD requests. Auth response codes not in this list are proxied to the client as-is regardless of request method.

- **Type:** `[]int`
- **Default:** `[401]`

```go
// Also redirect on 403
mforwardauth.WithRedirectStatusCodes(401, 403)
```

## Forwarded Headers

The middleware sets the following headers on the auth request:

| Header | Value |
|---|---|
| `X-Forwarded-Method` | Original request HTTP method |
| `X-Forwarded-Proto` | Original request protocol (`http` or `https`) |
| `X-Forwarded-Host` | Original request `Host` header |
| `X-Forwarded-Uri` | Original request URI |
| `X-Forwarded-For` | Client IP address |

All original request headers are also forwarded (unless `AuthRequestHeaders` is set as an allowlist).

## Complete Example

```go
package main

import (
    "net/http"
    "time"

    "github.com/rakunlabs/ada"
    mforwardauth "github.com/rakunlabs/ada/middleware/forwardauth"
)

func main() {
    mux := ada.New()

    // Add ForwardAuth middleware
    mux.Use(mforwardauth.Middleware(
        mforwardauth.WithAddress("http://auth-service:9000/verify"),
        mforwardauth.WithAuthResponseHeaders("X-Forwarded-User", "X-Auth-Roles"),
        mforwardauth.WithRedirectURL("https://login.example.com?rd={url}"),
        mforwardauth.WithTimeout(10 * time.Second),
    ))

    mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
        user := r.Header.Get("X-Forwarded-User")
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"message": "Hello, ` + user + `!"}`))
    })

    http.ListenAndServe(":8080", mux)
}
```

## Common Scenarios

### Basic Authentication Gate

```go
mforwardauth.Middleware(
    mforwardauth.WithAddress("http://auth:9000/verify"),
)
```

### With Login Page Redirect

```go
mforwardauth.Middleware(
    mforwardauth.WithAddress("http://auth:9000/verify"),
    mforwardauth.WithAuthResponseHeaders("X-Forwarded-User"),
    mforwardauth.WithRedirectURL("https://login.example.com?rd={url}"),
)
```

### Behind Another Proxy

When your application sits behind a reverse proxy (like Nginx or Traefik) that already sets `X-Forwarded-*` headers:

```go
mforwardauth.Middleware(
    mforwardauth.WithAddress("http://auth:9000/verify"),
    mforwardauth.WithTrustForwardHeader(true),
)
```

### Protect Specific Routes

Apply ForwardAuth only to specific route groups:

```go
mux := ada.New()

// Public routes - no auth
mux.GET("/health", healthHandler)

// Protected routes - require auth
api := mux.Group("/api",
    mforwardauth.Middleware(
        mforwardauth.WithAddress("http://auth:9000/verify"),
        mforwardauth.WithAuthResponseHeaders("X-Forwarded-User"),
    ),
)
api.GET("/users", usersHandler)
api.POST("/users", createUserHandler)
```

## Auth Service Response Behavior

| Original Method | Auth Response | RedirectURL Set? | Result |
|---|---|---|---|
| GET | 200 | - | Request forwarded to backend |
| GET | 401 | Yes | 302 redirect to login page |
| GET | 401 | No | 401 returned to client |
| GET | 403 | Yes | 403 returned to client (not in default redirect codes) |
| GET | 500 | Yes | 500 returned to client |
| POST | 401 | Yes | 401 returned to client (no redirect for POST) |
| POST | 200 | - | Request forwarded to backend |
| Any | connection error | - | 502 Bad Gateway |
