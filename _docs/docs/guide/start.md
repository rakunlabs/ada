# Start Server

Ada serves HTTP/1.1 and HTTP/2 (including unencrypted HTTP/2), so you can register gRPC handlers next to regular HTTP handlers.

## Start With a Context

Start the server with a context to shut it down automatically when the context is done:

```go
server := ada.New()
// ...
server.StartWithContext(ctx, ":8080")
```

## Shutdown Timeout

On shutdown, in-flight requests get up to `10s` to finish by default. Change it with `WithShutdownTimeout`:

```go
ada.New(ada.WithShutdownTimeout(30 * time.Second))
```

If the deadline expires, the remaining connections are force-closed and `Stop` returns an error.

## Manual Lifecycle

To manage the lifecycle yourself, call `server.Start(":8080")` and stop it with `server.Stop()`:

```go
server := ada.New()

go func() {
    if err := server.Start(":8080"); err != nil {
        log.Fatal(err)
    }
}()

// ...
if err := server.Stop(); err != nil {
    log.Println(err)
}
```

::: tip
`context.AfterFunc(ctx, func() { server.Stop() })` gives you the same behavior as `StartWithContext` when you need to wire the stop signal yourself.
:::

## Header Read Timeout

The underlying `http.Server` uses a `ReadHeaderTimeout` of `10s` by default. Change it per start:

```go
server.Start(":8080", ada.WithReadHeaderTimeout(5*time.Second))
```
