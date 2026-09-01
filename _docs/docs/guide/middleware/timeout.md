# Timeout

This middleware derives the request context with `context.WithTimeout`, so the
context is cancelled once the deadline passes.

```go
"github.com/rakunlabs/ada/middleware/timeout"
```

Add it to the mux, a group, or a single route:

```go
server.Use(timeout.Middleware(10 * time.Second))

// Or tighter on one slow endpoint only:
server.GET("/report", reportHandler, timeout.Middleware(30*time.Second))
```

A `timeout <= 0` makes the middleware a no-op — handy for wiring the value
straight from configuration.

::: warning Cancellation is cooperative
The middleware cancels the **context**; it does not write a response or stop
the handler for you. The handler (and everything it calls — database drivers,
`http.Client`, etc.) must honour `r.Context()` for the timeout to have any
effect, and decide what to answer when `ctx.Err()` reports
`context.DeadlineExceeded`:

```go
server.GET("/report", func(c *ada.Context) error {
    if err := slowQuery(c.Request.Context()); err != nil {
        if errors.Is(err, context.DeadlineExceeded) {
            return ada.NewHTTPError(http.StatusGatewayTimeout, "report timed out")
        }

        return err
    }

    return c.SendString("done")
})
```
:::

Note that the server itself also has read/write timeouts — see
[Start Server](../start) — which bound the connection rather than the
handler's work; the two complement each other.
