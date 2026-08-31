# Body Limit

The body-limit middleware caps the size of request bodies before a handler can
read them. It protects every handler in the chain, not only the ones that use
[binding](../binding), and it rejects oversized requests with a `413 Content Too
Large` response.

```go
import "github.com/rakunlabs/ada/middleware/bodylimit"
```

Add the middleware to the mux, a group, or a single handler; usually placed near
the top of the chain, after `recover` and the request logger:

```go
mux.Use(bodylimit.Middleware(2 << 20)) // 2 MiB
```

The limit is a byte count and must be positive. `Middleware` panics at setup
time when `limit <= 0`, so a miscalculated constant fails at startup instead of
silently disabling the protection.

```go
bodylimit.Middleware(0)  // panics: no accidental "unlimited"
bodylimit.Middleware(-1) // panics
```

## Per-Group Limits

Apply different limits to sibling groups when their request-size policies
differ. The scopes do not overlap, so each route gets only its group's limit:

```go
api := mux.Group("/api")
api.Use(bodylimit.Middleware(2 << 20)) // 2 MiB for regular API traffic

upload := mux.Group("/upload")
upload.Use(bodylimit.Middleware(32 << 20)) // 32 MiB for this group only
```

Nested limits cannot raise an outer limit. Each middleware wraps the current
body with `http.MaxBytesReader`, so the limits compose and the smallest limit is
effective. For example, a 32 MiB group limit nested under a 2 MiB mux limit
still allows at most 2 MiB. An inner limit can tighten an outer limit, but it
cannot loosen one.

## How Enforcement Works

The middleware checks the size twice, and both checks matter.

1. **Before the body is read.** If `Content-Length` is present and larger than
   the limit, the request is rejected immediately with `413`. Nothing is read
   from the connection, so a client announcing a 4 GiB upload costs the server
   almost nothing.
2. **While the body is read.** The body is replaced with
   `http.MaxBytesReader(w, r.Body, limit)`. When the actual bytes exceed the
   limit, the read fails with `*http.MaxBytesError`.

The header check alone is not enough. `Content-Length` is client-supplied and is
absent entirely for `Transfer-Encoding: chunked` requests, so a client can send
an unbounded body with no header at all, or send a small header and then keep
writing. The second layer is what actually bounds memory: `MaxBytesReader`
stops the read at the limit regardless of what the client claimed.

The first check is not redundant either — without it, a hostile
`Content-Length` would still be streamed up to the limit on every request
before being rejected. Together the two layers give a cheap rejection for
honest clients and a hard bound for dishonest ones.

### Handling The Read-Time Error

The header check produces the response itself. A read-time overflow surfaces as
an error in your handler, because only the handler knows how it wants to answer:

```go
func handler(c *ada.Context) error {
    var payload Payload
    if err := c.Bind(&payload); err != nil {
        return err // bind reports the overflow as 413
    }
    // ...
}
```

`bind` recognizes `*http.MaxBytesError` and reports it as `413`. When reading
`r.Body` directly, check for it yourself:

```go
data, err := io.ReadAll(r.Body)
if err != nil {
    var maxErr *http.MaxBytesError
    if errors.As(err, &maxErr) {
        http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
        return
    }
    // ...
}
```

## Skipping Requests

`WithSkipper` disables the limit for selected requests. The function runs per
request; returning `true` passes the request through untouched, with no
`Content-Length` check and no wrapped body.

```go
mux.Use(bodylimit.Middleware(
    2<<20,
    bodylimit.WithSkipper(func(r *http.Request) bool {
        return r.Method == http.MethodGet || r.Method == http.MethodHead
    }),
))
```

::: warning
A skipped request has no size protection from that middleware. Prefer
non-overlapping groups when routes need different limits. If you instead skip
an upload path in a global limiter, apply a separate limit to the upload group
so the skipped requests remain bounded.
:::

## Rejection Response

A request rejected by the `Content-Length` check is answered with status `413`
and a JSON body:

```json
{
  "error": "body_too_large",
  "message": "request body exceeds 2097152 bytes"
}
```

The `message` names the configured limit in bytes so a client can tell the
difference between "too big" and "wrong endpoint" without reading the server
logs. `error` is a stable machine-readable code; match on it rather than on the
message text.

## Relation To `bind`

`bind` has no default body limit — reaching for it is a per-call decision:

```go
c.Bind(&payload, bind.WithBodyLimit(4<<20))
```

That option only guards the one call site that uses it. This middleware guards
the whole route, including handlers that read `r.Body` directly, decode a
stream, or hand the body to another package. Use the middleware as the baseline
and `bind.WithBodyLimit` only for endpoints that need a tighter cap than the
route's.

See [Binding](../binding#request-body-limit) for details.
