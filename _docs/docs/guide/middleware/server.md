# Server

> https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Server

This middleware adds the `Server` HTTP header to responses, indicating the server software being used.

> Sometimes it's useful to identify the server software for debugging, analytics, or compliance purposes.  
> However, be cautious as exposing server information can also pose security risks.

```go
mserver "github.com/rakunlabs/ada/middleware/server"
```

Add middleware to directly mux, group or handler; usually placed in the top of the middleware chain:

```go
mserver.Middleware("my-server:v1.2.3")
```
