# Encoding

Compresses response bodies with `gzip` when the client advertises support for it in the `Accept-Encoding` header.

## Import

```go
mencoding "github.com/rakunlabs/ada/middleware/encoding"
```

## Usage

```go
server.Use(mencoding.Middleware())
```

## Options

Configure the middleware with `mencoding.WithConfig`:

```go
mencoding.Middleware(
    mencoding.WithConfig(mencoding.Config{
        Disabled: false,
        Encoding: []string{"gzip"},
    }),
)
```

| Field | Type | Default | Description |
|---|---|---|---|
| `Disabled` | `bool` | `false` | Skip negotiation and compression. The configuration is still validated |
| `Encoding` | `[]string` | `[]string{"gzip"}` | Enabled encodings. Only `gzip` is supported |

::: warning Invalid configuration panics
Encoding names are trimmed and matched case-insensitively at construction. Empty, duplicate, or unsupported values panic, even when `Disabled` is true, so a configuration error cannot stay hidden until the middleware is enabled.
:::

## Negotiation

The middleware follows RFC 9110 quality values and gives an explicit coding
preference precedence over `*`. Malformed q-values are conservatively treated as
`q=0`; `identity` remains acceptable unless explicitly disabled by
`identity;q=0` or by `*;q=0` without a more specific identity value. Duplicate
coding entries use the lowest stated quality.

## Streaming

Eligible responses are compressed as they stream, regardless of body size. No
minimum-size buffer is used because buffering would change streaming behavior.
If gzip overhead matters for tiny bodies, scope the middleware to routes that
produce responses worth compressing.
