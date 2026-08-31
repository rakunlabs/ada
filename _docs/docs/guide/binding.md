# Binding

HTTP request binding system that automatically maps HTTP request data to Go structs using struct tags.

## Basic Usage

```go
package main

import (
    "net/http"
    "github.com/rakunlabs/ada/utils/bind"
)

type User struct {
    ID       int    `json:"id"`
    Username string `json:"username" form:"username"`
    Email    string `json:"email" form:"email"`
    Page     int    `query:"page"`
    APIKey   string `header:"X-API-Key"`
}

func handleUser(w http.ResponseWriter, r *http.Request) {
    var user User
    if err := bind.Bind(r, &user); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // user is now populated with data from the request
}

// //////////////////////////////////
// if using the ada.Context function

func handleUser(c *ada.Context) error {
    var user User
    if err := c.Bind(&user); err != nil {
        return c.SetStatus(http.StatusBadRequest).Err(err)
    }

    // user is now populated with data from the request
}
```

## Request Body Limit

Binding applies **no body limit by default** (`bind.DefaultBodyLimit` is `0`).
An unbounded body is therefore an unbounded resource cost: JSON, XML and
URL-encoded bodies are read entirely into memory, while multipart bodies spool
to disk once they exceed the in-memory threshold described below.

Set a limit for every route with the
[body-limit middleware](./middleware/bodylimit), which protects the entire
handler rather than only the bind call:

```go
mux.Use(bodylimit.Middleware(2 << 20)) // 2 MiB
```

`bind.WithBodyLimit` sets a limit for a single bind, useful when one endpoint
needs a tighter cap than the route's:

```go
err := bind.Bind(r, &payload, bind.WithBodyLimit(4<<20)) // 4 MiB
```

`ada.Context.Bind` accepts the same options:

```go
err := c.Bind(&payload, bind.WithBodyLimit(4<<20))
```

The limit also applies when `Content-Length` is absent, and all bytes in the
body count toward it, including trailing whitespace. Exceeding it — whether the
limit came from the middleware or from `WithBodyLimit` — is reported as
`413 Content Too Large` with a message naming the limit, not as a generic `500`.

Passing `0` disables the limit explicitly, which is the default.

## Multipart Memory Threshold

`bind.DefaultMultipartFormMaxMemory` (32 MiB) is passed to
`http.Request.ParseMultipartForm`. Despite the name it is **not a limit and it
never rejects anything** — it only decides where the data goes:

- File parts are buffered in memory up to that many bytes. Go reserves a further
  10 MiB for the non-file parts, so the real memory ceiling is roughly
  `MaxMemory + 10 MiB`.
- Everything beyond that is written to **temporary files on disk**. An upload of
  any size will be accepted; it just stops consuming memory and starts consuming
  disk.

So a multipart endpoint with no body limit is a disk-exhaustion risk, not a
memory one. Use the [body-limit middleware](./middleware/bodylimit) to bound it.

The temporary files are removed for you: `net/http` clears them after the
handler returns, and `bind` clears them itself when it was the code that parsed
the form.

This threshold is now fully reachable. It was previously unreachable: the old
1 MiB total body cap rejected any request large enough to approach it.

## Supported Struct Tags

Own struct types can implement the `encoding.TextUnmarshaler` interface for custom parsing logic.

| Tag                    | Description                     | Example                    |
| ---------------------- | ------------------------------- | -------------------------- |
| `json:"field_name"`    | Binds from JSON request body    | `json:"username"`          |
| `xml:"field_name"`     | Binds from XML request body     | `xml:"title"`              |
| `form:"field_name"`    | Binds from form data            | `form:"first_name"`        |
| `query:"param_name"`   | Binds from URL query parameters | `query:"page"`             |
| `header:"Header-Name"` | Binds from HTTP headers         | `header:"User-Agent"`      |
| `uri:"param_name"`     | Binds from URI path parameters  | `uri:"user_id"`            |
| `param:"param_name"`   | Alternative to `uri`            | `param:"category"`         |
| `file:"field_name"`    | Binds uploaded files            | `file:"avatar"`            |
| `time_format:"layout"` | Custom time parsing format      | `time_format:"2006-01-02"` |

### Ignoring Binding Sources

Use `"-"` to explicitly exclude a field from a specific binding source:

```go
type Request struct {
    // Only binds from header, ignores JSON and form data
    Token string `json:"-" form:"-" header:"X-Token"`
    
    // Only binds from query params
    Filter string `json:"-" form:"-" query:"filter"`
}
```

## Supported Data Types

- **Primitives**: `string`, `int`, `int8`, `int16`, `int32`, `int64`, `uint`, `uint8`, `uint16`, `uint32`, `uint64`, `float32`, `float64`, `bool`
- **Slices**: `[]string`, `[]int`, `[]bool`, etc. (see
  [Query Value Separator](#query-value-separator) for how a query parameter
  fills one)
- **Pointers**: `*string`, `*int`, etc. (for optional fields)
- **Time**: `time.Time` with customizable parsing format
- **Duration**: `time.Duration`
- **Files**: `*multipart.FileHeader`, `[]*multipart.FileHeader`
- **Nested Structs**: Full support for nested struct binding
- **JSON RawMessage**: `json.RawMessage`, `[]json.RawMessage` for raw JSON preservation
- **Maps**: `map[string]any` and other map types (auto JSON unmarshal from form/query)

## Query Value Separator

A query parameter can fill a scalar-valued slice by repeating the parameter or
using `,` (`bind.DefaultQuerySeparator`):

```go
type Request struct {
    Tags []string `query:"tags"`
}
```

```
?tags=go&tags=web   → ["go" "web"]
?tags=go,web        → ["go" "web"]
?tags=go,web&tags=x → ["go" "web" "x"]
```

The separator does not apply to scalar fields:

```go
type Request struct {
    Name string `query:"name"`
}
```

```
?name=Doe,%20John   → "Doe, John"
```

Use `bind.WithQuerySeparator` to change the separator, or pass `""` to disable
splitting so that repeating the parameter is the only way to fill a slice:

```go
err := bind.Bind(r, &req, bind.WithQuerySeparator("|")) // ?tags=go|web
err := bind.Bind(r, &req, bind.WithQuerySeparator(""))  // ?tags=go&tags=web only
```

The option affects query binding only, not forms, headers, or URI parameters.
It does not split JSON-valued slices (`[]json.RawMessage`, slices of structs or
maps, and pointer variants); repeat the parameter to provide multiple JSON
values.

For repeated scalar parameters, the first value wins:

```
?v=bir&v=iki   →  Scalar string `query:"v"`   binds "bir"
?v=bir&v=iki   →  Slice []string `query:"v"`  binds ["bir" "iki"]
```

Malformed query strings, such as `?bad=%zz`, return a binding error.

## Binding Priority Order

When a field has multiple binding tags, sources are applied in this order (later sources override earlier ones):

1. JSON/XML/Form body (based on Content-Type)
2. Query parameters
3. Headers
4. URI parameters

```go
type Request struct {
    // If all sources have a value, header wins
    Value string `json:"value" query:"value" header:"X-Value"`
}
```

**Note:** Each binding source only sets a field if it has a value. For example, header binding only occurs if the header exists in the request. If a header is missing, the field retains its previous value (from JSON, query, etc.) or remains at its zero value.

## JSON RawMessage Support

Use `json.RawMessage` to preserve raw JSON strings without parsing:

```go
type Request struct {
    // Single raw JSON value
    Data json.RawMessage `form:"data" query:"data"`
    
    // Multiple raw JSON values
    Items []json.RawMessage `form:"items" query:"items"`
}
```

This is useful when you need to forward JSON data or defer parsing.

## Nested Struct Binding from Form/Query

When sending multipart form or query data with nested JSON objects, the binder automatically unmarshals JSON strings into struct and map fields:

```go
type Address struct {
    Street string `json:"street"`
    City   string `json:"city"`
}

type Request struct {
    Name    string         `form:"name"`
    Address Address        `form:"address"`  // Auto JSON unmarshal
    Meta    map[string]any `form:"meta"`     // Auto JSON unmarshal
    Items   []Address      `form:"items"`    // Slice of structs
}
```

Send as multipart form:

```
--boundary
Content-Disposition: form-data; name="name"

John
--boundary
Content-Disposition: form-data; name="address"

{"street":"123 Main St","city":"NYC"}
--boundary
Content-Disposition: form-data; name="items"

{"street":"456 Oak Ave","city":"LA"}
--boundary
Content-Disposition: form-data; name="items"

{"street":"789 Pine Rd","city":"SF"}
--boundary--
```

## Independent Binding Sources

To ensure a field only binds from one specific source, use `"-"` to exclude other sources:

```go
type Request struct {
    // Only from JSON body
    FromJSON string `json:"from_json" form:"-" query:"-" header:"-"`

    // Only from form data
    FromForm string `json:"-" form:"from_form" query:"-" header:"-"`

    // Only from query params
    FromQuery string `json:"-" form:"-" query:"from_query" header:"-"`

    // Only from header
    FromHeader string `json:"-" form:"-" query:"-" header:"X-From-Header"`
}
```
