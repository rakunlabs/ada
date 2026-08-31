# Encoding

This middleware provides support for response encoding using `gzip` compression.  
It compresses the HTTP response body if the client indicates support for gzip encoding via the `Accept-Encoding` header.

```go
mencoding "github.com/rakunlabs/ada/middleware/encoding"
```

Add middleware to directly mux, group or handler:

```go
mencoding.Middleware()
```

## Configuration

You can configure the middleware using `mencoding.Option` functions.

```go
mencoding.Middleware(
    mencoding.WithConfig(mencoding.Config{
        Disabled: false,
        Encoding: []string{"gzip"}, // Supported encodings
    }),
)
```

Only `gzip` is implemented. Encoding names are trimmed and matched
case-insensitively at construction. Empty, duplicate, or unsupported configured
values panic, including when `Disabled` is true, so configuration errors cannot
remain hidden until the middleware is enabled.

The middleware follows RFC 9110 quality values and gives an explicit coding
preference precedence over `*`. Malformed q-values are conservatively treated as
`q=0`; `identity` remains acceptable unless explicitly disabled by
`identity;q=0` or by `*;q=0` without a more specific identity value. Duplicate
coding entries use the lowest stated quality.

Eligible responses are compressed as they stream, regardless of body size. No
minimum-size buffer is used because buffering would change streaming behavior.
If gzip overhead matters for tiny bodies, scope the middleware to routes that
produce responses worth compressing.
