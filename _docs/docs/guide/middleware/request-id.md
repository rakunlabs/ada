# Request ID

Request ID middleware is used to generate a unique identifier for each request.  
This ID can be used for logging, and debugging purposes. It helps in tracking requests across different services and systems.

```go
mrequestid "github.com/rakunlabs/ada/middleware/requestid"
```

Add middleware to directly mux, group or handler; usually placed in the top of the middleware chain:

```go
// mux.Use(
mrequestid.Middleware()
```

## Configuration

Default function to generate request IDs uses [github.com/oklog/ulid/v2](https://github.com/oklog/ulid)

```go
// change request ID generator to something else
mrequestid.Middleware(mrequestid.WithGenerateRequestID(func() string {
    return myCustomIDGenerator()
})),
```
