# Timeout

Derives the request context with `context.WithTimeout`, so the context is cancelled once the deadline passes.

## Import

```go
"github.com/rakunlabs/ada/middleware/timeout"
```

## Usage

```go
server.Use(timeout.Middleware(10 * time.Second))

// Or tighter on one slow endpoint only:
server.GET("/report", reportHandler, timeout.Middleware(30*time.Second))
```

A `timeout <= 0` makes the middleware a no-op, which is handy when the value comes straight from configuration.

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

## Server Timeouts

The server itself also has a header read timeout (see
[Start Server](../start#header-read-timeout)). It bounds the connection rather
than the handler's work, so the two complement each other.
