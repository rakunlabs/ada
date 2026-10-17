# Swagger

Serves the Swagger UI and your generated API documentation, so you can browse and try your endpoints. The version and other details shown in the docs can be changed at runtime.

Uses [github.com/swaggo/swag](https://github.com/swaggo/swag) to generate the docs.

## Import

```go
"github.com/rakunlabs/ada/handler/swagger"
```

## Setup

### 1. Add the `swag` tool

Add `swaggo/swag` as a tool dependency so it is easy to run from `go generate`:

```sh
go get -tool github.com/swaggo/swag/cmd/swag@v1.16.6
```

### 2. Add general API info

Add the `go:generate` directive and the general API annotations, usually in `server.go`:

```go
//go:generate go tool swag init -pd -g swagger.go

// @title Hello API
// @description This is a sample server for Hello API.
// @contact.name API Support
// @contact.url http://www.example.com/support
// @contact.email support@example.com
func newServer() (*ada.Server, error) {
    ...
}
```

### 3. Annotate handlers

See the [swaggo/swag documentation](https://github.com/swaggo/swag#declarative-comments-format) for every annotation option.

```go
// @Summary Get Info
// @Description Returns information message
// @Tags hello
// @Accept json
// @Produce json
// @Param name query string true "Name"
// @Success 200 {object} map[string]string
// @Router /hello/info [get]
func (h *Hello) Info(c *ada.Context) error {
    ...
}
```

### 4. Generate and serve

Run `go generate ./...` to create the `docs` package, then register the handler:

```go
import (
    "github.com/rakunlabs/ada/handler/swagger"

    _ "example.com/myapp/docs" // generated docs, imported for side effects
)

mux.HandleFunc("/swagger/*", swagger.Handler(swagger.WithVersion("v0.1.0")))
```

::: warning
Don't forget the blank import of the generated `docs` package. Without it the UI loads, but `doc.json` fails to load the spec.
:::

## Options

These override the values from the generated spec at runtime:

| Option | Description |
|---|---|
| `WithVersion(string)` | API version |
| `WithTitle(string)` | API title |
| `WithDescription(string)` | API description |
| `WithHost(string)` | API host |
| `WithBasePath(string)` | API base path |
| `WithSchemes(...string)` | API schemes, e.g. `https` |
| `WithInfoInstanceName(string)` | Generated swag instance to serve. Default `swagger` |
| `WithConfigFns(...func(*Config))` | Customize the Swagger UI page |
