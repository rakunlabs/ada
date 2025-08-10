# Start Server

Ada server start default with http2 server which is allow you add gRPC handlers as well as HTTP handlers.
While starting the server, start with context which allow automatically shutdown the server when context is done.

```go
server := ada.New()
// ...
server.StartWithContext(ctx, ":8080")
```

Default server timeout is `10 seconds` but you can change it by setting the timeout option.

```go
ada.New(ada.WithShutdownTimeout(10 * time.Second))
```

If you want to manage by yourself than you can use `ada.New()` and call `server.Start(":8080")`.
For stopping the server don't forget to call `server.Stop()`.
Check `context.AfterFunc` for manually shutdown the server.
