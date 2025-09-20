# Context

Handlers are typically `func(w http.ResponseWriter, r *http.Request)`, but ada provides a wrapper called `ada.HandlerFunc` which is `func(c *ada.Context) error`. This adds useful methods to handle requests and responses more easily.

```go
func myHandler(c *ada.Context) error {
    var data MyData
    if err := c.Bind(&data); err != nil { // parse request body based on Content-Type
        return c.SetStatus(http.StatusBadRequest).Err(err)
    }

    // default status is 200 OK
    return c.SetHeader("X-Custom-Header", "value").SetStatus(http.StatusOK).SendJSON(data)
}
```

## Response Methods

### JSON Responses

Send JSON data with automatic content-type setting:

```go
// Send compact JSON
return c.SendJSON(data)

// Send pretty-printed JSON
return c.SendJSONP(data, "  ")

// Send raw JSON bytes
return c.SendJSONRaw(bytes.NewReader([]byte(`{"message": "hello"}`)))
```

### String Responses

Send plain text responses:

```go
return c.SendString("Hello, World!")
```

### File Responses

Send single files or multiple files as ZIP:

```go
// Send single file
file, _ := os.Open("example.txt")
defer file.Close()
return c.SendFile("example.txt", file)

// Send multiple files as ZIP
files := map[string]io.Reader{
    "file1.txt": strings.NewReader("content1"),
    "file2.txt": strings.NewReader("content2"),
}
return c.SendZip("archive.zip", files)
```

### Blob Responses

Send binary data with custom content-type:

```go
data := []byte("binary content")
return c.SendBlob("application/octet-stream", bytes.NewReader(data))
```

### No Content

Send 204 No Content response:

```go
return c.SendNoContent()
```

## Headers and Status

Set response headers and status codes fluently:

```go
return c.SetHeader("X-Custom-Header", "value").
       SetStatus(http.StatusCreated).
       SendJSON(data)
```

## Error Handling

`ada.HandlerFunc` returns an error, which can be handled by a custom error handler set on the server:

```go
server := ada.New()
server.ErrorHandler(func(c *ada.Context, err error) {
    // Custom error handling logic
    log.Printf("Error: %v", err)
    c.SetStatus(http.StatusInternalServerError).SendJSON(map[string]string{
        "error": "Internal server error",
    })
})
```

The default error handler checks if the error is an `ada.HandlerError` and uses its `Code` field as the HTTP status:

```go
var DefaultErrHandler = func(c *ada.Context, err error) {
    c.SendJSON(map[string]string{"message": err.Error()})
}
```

To return a `HandlerError` with a specific status code:

```go
func myHandler(c *ada.Context) error {
    return c.SetStatus(http.StatusBadRequest).Err(errors.New("id is required"))
}
```

This will return a 400 Bad Request with the error message in JSON format.
