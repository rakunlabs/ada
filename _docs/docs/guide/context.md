# Context

Handlers usually `func(w http.ResponseWriter, r *http.Request)` but we have also one wrapper around `http.HandlerFunc` called `ada.HandlerFunc` which is `func(c *ada.Context) error` that adds some useful methods to the request object.

```go
func myHandler(c *ada.Context) error {
    var data MyData
    if err := c.Bind(&data); err != nil { // parse JSON body
        return c.SetStatus(http.StatusBadRequest).Err(err)
    }

    // default status is 200 OK
    return c.SetHeader("X-Custom-Header", "value").SetStatus(http.StatusOK).SendJSON(data)
}
```

## Error Handling

`ada.HandlerFunc` returns an error, which can be handled by a custom error handler set on the server:

```go
// server := ada.New()
server.ErrorHandler(func(c *ada.Context, err error) {
    // ....
})
```

Our default handler like that, if `ada.HandlerError` is returned, it uses its `Code` field as HTTP status code, otherwise it returns `500 Internal Server Error`:

```go
var DefaultErrHandler = func(c *Context, err error) {
	var errResp *HandlerError
	if errors.As(err, &errResp) {
		c.SetStatus(errResp.Code).SendJSON(errResp)
		return
	}

	c.SetStatus(http.StatusInternalServerError).SendJSON(map[string]string{"message": err.Error()})
}
```

To return HandlerError from your handler:

```go
func myHandler(c *ada.Context) error {
    return c.SetStatus(http.StatusBadRequest).Err(errors.New("id is required")) // returns *ada.HandlerError
}
```
