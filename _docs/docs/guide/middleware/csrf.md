# CSRF

Protects unsafe requests (`POST`, `PUT`, `PATCH`, `DELETE`, …) against cross-site request forgery.

There are two layers:

- **Origin check** (always on unless disabled) uses the browser's `Sec-Fetch-Site` and `Origin` headers through Go's [`http.CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection). Clients need no changes.
- **Token check** (optional) implements the signed double-submit cookie pattern for clients that need an explicit token, such as server-rendered forms or very old browsers.

## Import

```go
mcsrf "github.com/rakunlabs/ada/middleware/csrf"
```

## Usage

```go
server.Use(mcsrf.Middleware())
```

`GET`, `HEAD`, `OPTIONS` and `TRACE` are always allowed, so handlers for safe methods must not change state.

Requests that send neither `Sec-Fetch-Site` nor `Origin` are treated as same-origin or non-browser requests and are allowed. API clients, `curl`, and server-to-server calls keep working.

## Configuration

```go
mcsrf.Middleware(
    mcsrf.WithConfig(mcsrf.Config{
        TrustedOrigins: []string{"https://app.example.com"},
        BypassPatterns: []string{"POST /webhook/{provider}"},
        Token: mcsrf.Token{
            Enabled: true,
            Secret:  os.Getenv("CSRF_SECRET"),
        },
    }),
)
```

| Field | Type | Default | Description |
|---|---|---|---|
| `TrustedOrigins` | `[]string` | empty | Cross-origin sources allowed to send unsafe requests, as `scheme://host[:port]` |
| `BypassPatterns` | `[]string` | empty | `http.ServeMux` patterns that skip every check, e.g. `POST /webhook/{id}` |
| `DisableOriginCheck` | `bool` | `false` | Turn off the origin check, leaving only the token check |
| `Token` | `Token` | disabled | Double-submit cookie settings, see below |
| `DenyHandler` | `http.Handler` | 403 JSON | Answers rejected requests |

Bypass patterns only match directly: a path that `ServeMux` would redirect (cleaned, or with a trailing slash added) is not bypassed.

### Token

| Field | Type | Default | Description |
|---|---|---|---|
| `Enabled` | `bool` | `false` | Turn the token check on |
| `Secret` | `string` | empty | HMAC-SHA256 key that signs the token. Set it in production |
| `SessionID` | `func(*http.Request) string` | `nil` | Returns the session or user identifier the token is bound to. Requires `Secret` |
| `CookieName` | `string` | `csrf_token` | Cookie carrying the token |
| `HeaderName` | `string` | `X-CSRF-Token` | Header the client echoes the token in |
| `FormField` | `string` | `csrf_token` | Form field checked for url-encoded and multipart posts when the header is empty |
| `MaxFormSize` | `int64` | `1 << 20` | Body limit when reading `FormField` from url-encoded posts. Larger bodies are rejected |
| `MaxMultipartMemory` | `int64` | `1 << 20` | Memory limit when parsing multipart posts. Larger file parts go to temporary files |
| `CookiePath` | `string` | `/` | Cookie path |
| `CookieDomain` | `string` | empty | Cookie domain |
| `CookieMaxAge` | `time.Duration` | `0` (session) | Cookie lifetime |
| `CookieInsecure` | `bool` | `false` | Drop the `Secure` attribute, for plain HTTP development only |
| `CookieSameSite` | `string` | `lax` | `lax`, `strict`, or `none` |

The cookie is not `HttpOnly`, because JavaScript has to read it and send it back in the header.

When a response issues a new token cookie, the middleware also adds `Vary: Cookie` and `Cache-Control: private` (removing `public` and `s-maxage`), so shared caches do not hand one user's token to another. An existing `private` or `no-store` is left as it is.

::: tip Signing, session binding and cookie prefixes
`Secret` stops clients from inventing tokens, but on its own a signed token is not tied to a user: a token an attacker got from your site is valid in any browser. A sibling subdomain that can set cookies for your domain could plant it in a victim's browser together with the matching value it already knows.

Set `SessionID` to bind the signature to the session, and name the cookie `__Host-csrf_token` (secure, no domain, path `/`) so subdomains cannot overwrite it:

```go
mcsrf.Token{
    Enabled:    true,
    Secret:     os.Getenv("CSRF_SECRET"),
    CookieName: "__Host-csrf_token",
    SessionID: func(r *http.Request) string {
        c, err := r.Cookie("session")
        if err != nil {
            return ""
        }
        return c.Value
    },
}
```

With `SessionID`, a token issued before login is bound to the empty identifier and stops being valid once the user logs in (or the session rotates or ends). The next safe request issues a fresh token, so make the client read the token again after login, for example by redirecting to a page after the login `POST`.
:::

::: info Form posts
When the header is empty, the middleware reads `FormField` from the body before the next handler runs, and the parsed form stays available in `r.Form`, `r.PostForm` and `r.MultipartForm`. Url-encoded bodies above `MaxFormSize` are rejected. Multipart forms, including HTML file uploads, are parsed with `MaxMultipartMemory`; file parts above it go to temporary files, which are removed after the next handler returns. To avoid parsing large uploads before authentication, send the token in the header instead.
:::

::: warning Invalid configuration panics
Malformed trusted origins, invalid or conflicting bypass patterns, an unknown `CookieSameSite`, `none` combined with `CookieInsecure`, a negative `CookieMaxAge`, `MaxFormSize` or `MaxMultipartMemory`, `SessionID` without `Secret`, and `__Host-` or `__Secure-` names whose attributes break the prefix rules all panic at construction.
:::

## How the Token Works

1. On a safe request without a valid cookie, the middleware issues a new random token in the cookie.
2. The client reads the cookie and sends the same value in the `X-CSRF-Token` header, or in the `csrf_token` form field.
3. On an unsafe request, the middleware checks that the cookie is valid and that the echoed value matches it. The comparison is constant-time.

A cross-site attacker can make the browser send the cookie but cannot read it, so it cannot produce the matching header.

### JavaScript Clients

```js
const token = document.cookie
  .split("; ")
  .find((c) => c.startsWith("csrf_token="))
  ?.split("=")[1];

await fetch("/api/items", {
  method: "POST",
  headers: { "X-CSRF-Token": token, "Content-Type": "application/json" },
  body: JSON.stringify(item),
});
```

### Server-Rendered Forms

`TokenFromRequest` returns the token for the current request, including a freshly issued one, so templates can embed it:

```go
func form(w http.ResponseWriter, r *http.Request) {
    tmpl.Execute(w, map[string]any{"CSRF": mcsrf.TokenFromRequest(r)})
}
```

```html
<form method="post" action="/items">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  …
</form>
```

## Custom Rejection

`Cause` reports why a request was rejected. It returns `ErrCrossOrigin`, `ErrTokenMissing`, or `ErrTokenInvalid`:

```go
mcsrf.Config{
    DenyHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        slog.Warn("csrf rejected", "cause", mcsrf.Cause(r), "path", r.URL.Path)
        http.Error(w, "forbidden", http.StatusForbidden)
    }),
}
```

## Placement

Put CSRF after [CORS](./cors) and before any handler that changes state. Preflight `OPTIONS` requests are always allowed, so the order does not affect them. A cross-origin frontend that legitimately calls your API must be listed in both `AllowOrigins` for CORS and `TrustedOrigins` for CSRF.
