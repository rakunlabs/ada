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
