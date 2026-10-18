# Encoding

Compresses response bodies with `zstd`, `br` (Brotli), or `gzip`, depending on what the client advertises in the `Accept-Encoding` header.

## Import

```go
mencoding "github.com/rakunlabs/ada/middleware/encoding"
```

## Usage

```go
server.Use(mencoding.Middleware())
```

The defaults are a good fit for most APIs and web apps. All three encodings are enabled, bodies under 1 KiB are not compressed, and formats that are already compressed (images, video, archives) are skipped.

## Options

Configure the middleware with `mencoding.WithConfig`:

```go
brotliLevel := 5

mencoding.Middleware(
    mencoding.WithConfig(mencoding.Config{
        Encoding:             []string{"br", "gzip"},
        MinLength:            512,
        IncludedContentTypes: []string{"text/*", "application/json"},
        BrotliLevel:          &brotliLevel,
    }),
)
```

| Field | Type | Default | Description |
|---|---|---|---|
| `Disabled` | `bool` | `false` | Skip negotiation and compression. The configuration is still validated |
| `Encoding` | `[]string` | `zstd, br, gzip` | Enabled encodings, in server preference order |
| `MinLength` | `int` | `1024` | Minimum body size in bytes to compress. Use `1` to compress every non-empty body |
| `ExcludedContentTypes` | `[]string` | `DefaultExcludedContentTypes` | Content types that are never compressed. Supports `type/*` |
| `IncludedContentTypes` | `[]string` | empty | When set, only these content types are compressed and `ExcludedContentTypes` is ignored |
| `GzipLevel` | `*int` | `gzip.DefaultCompression` | Range `-2`..`9` |
| `BrotliLevel` | `*int` | `4` | Range `0`..`11`. `4` suits dynamic content and `11` suits static assets |
| `ZstdLevel` | `*int` | encoder default | Range `1`..`22` |

::: warning Invalid configuration panics
Encoding names are trimmed and matched case-insensitively at construction. Empty, duplicate, or unsupported encodings, a negative `MinLength`, and out-of-range levels for enabled encodings all panic, even when `Disabled` is true, so a configuration error cannot stay hidden until the middleware is enabled.
:::

## Negotiation

The middleware follows RFC 9110 quality values and gives an explicit coding
preference precedence over `*`. If the client gives several encodings the same
quality, the server preference order in `Encoding` decides. For example,
`Accept-Encoding: gzip, br, zstd` selects `zstd` with the default order.

Malformed q-values are conservatively treated as `q=0`. `identity` remains
acceptable unless explicitly disabled by `identity;q=0` or by `*;q=0` without a
more specific identity value; when no encoding is acceptable the response is
`406 Not Acceptable`. Duplicate coding entries use the lowest stated quality.

`Vary: Accept-Encoding` is added to every negotiated response.

## Content Types

`DefaultExcludedContentTypes` covers already compressed formats:
`image/*`, `video/*`, `audio/*`, `font/woff`, `font/woff2`, zip, gzip, zstd,
7z and rar archives, `application/octet-stream`, and `application/grpc`. While
this default list is in use, compressible images such as `image/svg+xml`,
`image/bmp`, and `image/x-icon` are still compressed.

Matching ignores parameters such as `charset`. When the handler does not set
`Content-Type`, it is sniffed from the first buffered bytes before the decision
is made.

To compress every content type, pass an empty, non-nil slice:

```go
mencoding.Config{ExcludedContentTypes: []string{}}
```

## Skipped Responses

A response is sent as is when:

- the request is `HEAD`, or a connection upgrade such as WebSocket (the handler
  receives the original `ResponseWriter` so it can hijack the connection)
- the status is `1xx`, `204`, `206`, or `304`
- the handler already set `Content-Encoding` or `Content-Range`
- `Cache-Control` contains `no-transform`
- the content type is filtered out, or the body is smaller than `MinLength`

When a body is compressed, `Content-Length` is removed and a strong `ETag` is
weakened to `W/"…"`, because the encoded bytes differ from the original
representation.

## Streaming

Up to `MinLength` bytes are buffered to decide whether compression is worth it.
A `Flush` (or `http.ResponseController.Flush`) ends buffering immediately and
starts compressing, so Server-Sent Events and other streaming responses are not
delayed. Every encoder flushes its pending output on `Flush`. zstd runs
synchronously with an 8 MiB window, which browsers support.

Encoders are pooled per encoding and level, so steady-state requests do not
allocate new compressors.
