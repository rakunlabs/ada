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
The request body is **never** sent to the auth service. Only headers are forwarded. Body-shape headers (`Content-Length`, `Content-Type`, `Content-Encoding`, `Transfer-Encoding`) are stripped from the auth request so the auth service is not misled about a payload that isn't there.
:::

::: info
`Middleware(...)` validates the configuration at construction time and **panics** on invalid config (empty `Address`, non-3xx `RedirectCode`, malformed `AuthResponseHeadersRegex`). This fails fast at startup rather than on the first request. Use `New(...).Validate()` if you prefer to handle the error yourself.
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

Any header listed in the incoming `Connection` header is also treated as hop-by-hop (RFC 7230 §6.1) and stripped even when it appears in this allowlist. Body-shape headers are always stripped.

- **Type:** `[]string`
- **Default:** `[]` (forward all)

```go
// Only forward Authorization and Cookie headers to auth service
mforwardauth.WithAuthRequestHeaders("Authorization", "Cookie")
```

### DeleteRequestHeaders

Headers to delete from the original request before invoking the next handler. Applied **before** `AuthResponseHeaders` are copied, so an auth-set header of the same name replaces a deleted one rather than being dropped.

Useful for stripping client-supplied headers that would otherwise shadow identity headers set by the auth service (e.g. a client spoofing `X-Forwarded-User`).

- **Type:** `[]string`
- **Default:** `[]`

```go
mforwardauth.WithDeleteRequestHeaders("X-Forwarded-User", "X-Auth-Token")
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

The HTTP status code to use for the redirect. Must be a 3xx status code; any other value causes `Middleware(...)` to panic at construction time.

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

### Client, Transport, RootCAs, ClientCert

Escape hatches for talking to auth services that require a custom HTTP client, a private TLS trust anchor, or mutual TLS.

| Option | Type | Purpose |
|---|---|---|
| `WithClient` | `*http.Client` | Replace the internal client entirely. Timeout / TLS / transport options below are ignored. |
| `WithTransport` | `http.RoundTripper` | Replace the default transport on the built-in client. Ignored when `WithClient` is set. |
| `WithRootCAs` | `*x509.CertPool` | Root CA pool used to verify the auth service certificate. Useful for private PKI. Ignored when `WithClient` or `WithTransport` is set. |
| `WithClientCert` | `tls.Certificate` | Client certificate presented to the auth service during the TLS handshake (mTLS). Ignored when `WithClient` or `WithTransport` is set. |

```go
// Verify the auth service with a private CA
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(caPEM)

mforwardauth.Middleware(
    mforwardauth.WithAddress("https://auth.internal:9000/verify"),
    mforwardauth.WithRootCAs(pool),
)
```

```go
// mTLS to the auth service
cert, _ := tls.LoadX509KeyPair("client.crt", "client.key")

mforwardauth.Middleware(
    mforwardauth.WithAddress("https://auth.internal:9000/verify"),
    mforwardauth.WithClientCert(cert),
)
```

### Extractor

A post-auth hook that receives the auth service's **response body** along with the original request. The extractor can decode the body into any structured type and stash it on the request context so downstream handlers/middleware see a typed user object instead of a pile of string headers.

- **Type:** `ExtractorFunc = func(r *http.Request, resp *http.Response) (*http.Request, error)`
- **Default:** `nil` (body is drained and discarded, as today)

When set, the extractor runs **only on 2xx responses**, **after** `AuthResponseHeaders` have been copied onto the request. Returning an error fails the request with `502 Bad Gateway` (fail closed).

::: info
The extractor is an escape hatch — you get the full `*http.Response` and return a new `*http.Request` with whatever context values you want. The built-in `IdentityExtractor` covers the common case.
:::

#### IdentityExtractor (batteries included)

Drop-in extractor that JSON-decodes the auth body into the project's standard `identity.Identity` type and stores it via `identity.WithContext`. Downstream handlers read it back with `identity.FromContext`.

```go
mforwardauth.Middleware(
    mforwardauth.WithAddress("http://auth/verify"),
    mforwardauth.WithExtractor(mforwardauth.IdentityExtractor),
)

// downstream
func handler(w http.ResponseWriter, r *http.Request) {
    id := identity.FromContext(r.Context())
    if id == nil {
        http.Error(w, "no identity", http.StatusUnauthorized)
        return
    }
    // id.Subject, id.Email, id.Roles, id.Scopes, id.Claims...
}
```

The auth service must return a 2xx JSON body matching `identity.Identity`, for example:

```json
{
  "subject": "alice",
  "email": "alice@example.com",
  "email_verified": true,
  "roles": ["admin", "editor"],
  "scopes": ["read", "write"],
  "claims": {"org": "acme"},
  "provider": "oidc"
}
```

Empty body, malformed JSON, or a body exceeding `MaxBodySize` all fail closed with `502 Bad Gateway`.

#### Custom extractor

For a user-defined type, bring your own context key and decoder:

```go
type AppUser struct {
    ID    string   `json:"id"`
    Tier  string   `json:"tier"`
    Flags []string `json:"flags"`
}

type appUserKey struct{}

mforwardauth.Middleware(
    mforwardauth.WithAddress("http://auth/verify"),
    mforwardauth.WithExtractor(func(r *http.Request, resp *http.Response) (*http.Request, error) {
        var u AppUser
        if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
            return nil, fmt.Errorf("decode auth body: %w", err)
        }
        return r.WithContext(context.WithValue(r.Context(), appUserKey{}, &u)), nil
    }),
)
```

### MaxBodySize

Caps how much of the auth response body the extractor may read. Protects against a misbehaving auth service streaming a large payload. Ignored when no extractor is set.

- **Type:** `int64`
- **Default:** `1 << 20` (1 MiB)

```go
mforwardauth.WithMaxBodySize(1 << 20) // 1 MiB
mforwardauth.WithMaxBodySize(4 << 10) // 4 KiB
```

Reading past the cap returns `*http.MaxBytesError` from `resp.Body`; extractors that surface it fail the request with `502 Bad Gateway`.

### OnError

Callback invoked when the call to the auth service fails (network error, timeout, connection refused). Purely observational — the response to the client is still `502 Bad Gateway`. Use it to plug in a logger or metric.

- **Type:** `func(err error, r *http.Request)`
- **Default:** `nil`

```go
mforwardauth.Middleware(
    mforwardauth.WithAddress("http://auth:9000/verify"),
    mforwardauth.WithOnError(func(err error, r *http.Request) {
        log.Printf("forwardauth: %s %s: %v", r.Method, r.URL.Path, err)
    }),
)
```

## Forwarded Headers

The middleware sets the following headers on the auth request:

| Header | Value |
|---|---|
| `X-Forwarded-Method` | Original request HTTP method |
| `X-Forwarded-Proto` | Original request protocol (`http` or `https`) |
| `X-Forwarded-Host` | Original request `Host` header |
| `X-Forwarded-Uri` | Original request URI |
| `X-Forwarded-For` | Client IP, appended to the existing chain when `TrustForwardHeader` is true |

All original request headers are also forwarded (unless `AuthRequestHeaders` is set as an allowlist). Hop-by-hop headers, any header listed in the incoming `Connection` header, and body-shape headers (`Content-Length`, `Content-Type`, `Content-Encoding`, `Transfer-Encoding`) are never forwarded.

::: info
With `TrustForwardHeader: true`, `X-Forwarded-For` is **extended** with the immediate client IP rather than replaced, so the auth service sees the full chain: `X-Forwarded-For: original-client, middle-proxy, your-proxy`. `X-Forwarded-{Proto,Host,Uri,Method}` are reused from the incoming request when present.
:::

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
