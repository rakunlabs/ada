# Binding

HTTP request binding system that automatically maps HTTP request data to Go structs using struct tags.

## Supported Struct Tags

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

## Supported Data Types

- **Primitives**: `string`, `int`, `int8`, `int16`, `int32`, `int64`, `uint`, `uint8`, `uint16`, `uint32`, `uint64`, `float32`, `float64`, `bool`
- **Slices**: `[]string`, `[]int`, `[]bool`, etc.
- **Pointers**: `*string`, `*int`, etc. (for optional fields)
- **Time**: `time.Time` with customizable parsing format
- **Duration**: `time.Duration`
- **Files**: `*multipart.FileHeader`, `[]*multipart.FileHeader`
- **Nested Structs**: Full support for nested struct binding

### Basic Usage

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
