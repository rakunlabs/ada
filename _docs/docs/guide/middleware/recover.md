# Recover

Recover middleware is used to recover from panics in your application.  
It ensures that your application can continue to run even if an unexpected error occurs, by catching the panic and allowing you to handle it gracefully.

```go
mrecover "github.com/rakunlabs/ada/middleware/recover"
```

By default, a recovered panic returns HTTP 500 with the body `Internal Server Error`
(followed by a newline). Panic details are never included in the default response.
The original panic is logged using the configured logger, and a stack trace is
printed to standard error by default. Use `WithLogger(nil)` to disable logging
and `WithPrintStack(false)` to disable stack traces.

## Custom Error Handler

Use `WithErrorHandler(func(http.ResponseWriter, *http.Request, error))` to share
your application's error response handling without wrapping individual handlers:

```go
handler := mrecover.Middleware(
    mrecover.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
        // Use err internally; return only information safe for clients.
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        _, _ = w.Write([]byte(`{"error":"internal server error"}`))
    }),
)(appHandler)
```

The callback receives the middleware's request and the original error when the
panic value implements `error`, preserving its identity for `errors.Is` and
`errors.As`. Other panic values are formatted with `%v` and converted to an error.
Logging and optional stack printing happen before the callback.

The callback replaces the default response entirely and owns the response status,
headers, body, and **redaction of sensitive information**. A nil callback restores
the default generic 500 response. Options are applied in order, so the last
`WithErrorHandler` wins. You can also set the exported `Recover.ErrorHandler`
field before serving requests. Do not change middleware configuration concurrently
with requests.

## Committed Responses

Once a handler writes a final status or body, flushes, or successfully hijacks the
connection, recovery cannot safely replace the response. The middleware logs the
panic, optionally prints its stack, and re-panics with `http.ErrAbortHandler` to
abort HTTP handling without appending another body or calling the error callback.
After a successful hijack, the handler owns and must close the connection.
Informational 1xx statuses do not commit the response, except for 101 Switching
Protocols. A panic of `http.ErrAbortHandler` itself is always propagated without
logging or invoking the callback.

Response writers are wrapped with `httpsnoop.Wrap`, preserving the underlying
writer's optional `http.Flusher`, `http.Hijacker`, `http.CloseNotifier`,
`http.Pusher`, and `io.ReaderFrom` interfaces, and providing `Unwrap` support.
`ReadFrom` is conservatively considered committed on entry because it can write
directly and panic during a partial transfer. Writes made directly to an unwrapped
writer bypass tracking; perform response writes through the wrapped writer.

Recovery applies to panics in the handler's serving goroutine. Panics in other
goroutines need recovery within those goroutines. Panics in the error callback
propagate to the caller; callbacks should not panic.
