# Swagger

Swagger is a middleware that serves the Swagger UI and API documentation for your application. It allows you to easily document and test your API endpoints and easy to change the version and other information in the generated Swagger docs.

```go
"github.com/rakunlabs/ada/handler/swagger"
```

Uses [github.com/swaggo/swag](https://github.com/swaggo/swag).

## Example

Add swaggo/swag in your project as tools dependency, this makes easier to use with `go generate`.

```sh
go get -tool github.com/swaggo/swag/cmd/swag@v1.16.6
```

Than add this in your go file usually in `server.go`

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

And add comments to your handlers.  
Check details swaggo/swag package for more annotation options.

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

Then in your server setup code add the swagger handler.

When you click the generate button it will generate the docs folder with swagger files.  
Don't forget to import the generated docs package for side effects.

```go
// "github.com/rakunlabs/ada/handler/swagger"
// _ "...../docs" # import generated docs package for side effects

mux.HandleFunc("/swagger/*", swagger.Handler(swagger.WithVersion("v0.1.0")))
```
