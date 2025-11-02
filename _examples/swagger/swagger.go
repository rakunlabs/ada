package swagger

import (
	"context"
	"net/http"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/ada/handler/swagger"

	mcors "github.com/rakunlabs/ada/middleware/cors"
	mencoding "github.com/rakunlabs/ada/middleware/encoding"
	mlog "github.com/rakunlabs/ada/middleware/log"
	mrecover "github.com/rakunlabs/ada/middleware/recover"
	mrequestid "github.com/rakunlabs/ada/middleware/requestid"
	mserver "github.com/rakunlabs/ada/middleware/server"
	mtelemetry "github.com/rakunlabs/ada/middleware/telemetry"

	_ "github.com/rakunlabs/ada/_examples/swagger/docs"
)

//go:generate go tool swag init -pd -g swagger.go

// Run starts the example server.
// @title Hello API
// @description This is a sample server for Hello API.
// @contact.name API Support
// @contact.url http://www.example.com/support
// @contact.email support@example.com
func Run(ctx context.Context) error {
	server, err := ada.NewWithFunc(ctx, func(ctx context.Context, mux *ada.Mux) error {
		helloHandler := &Hello{}

		mux.Use(
			mrecover.Middleware(),
			mserver.Middleware("MyServer"),
			mrequestid.Middleware(),
			mlog.Middleware(),
			mcors.Middleware(),
			mtelemetry.Middleware(),
			mencoding.Middleware(),
		)

		mux.HandleFunc("/swagger/*", swagger.Handler(swagger.WithVersion("v0.1.0")))

		mux.GET("/hello/info", mux.Wrap(helloHandler.Info))

		return nil
	})
	if err != nil {
		return err
	}

	return server.StartWithContext(ctx, ":8080")
}

type Hello struct{}

// @Summary Get Info
// @Description Returns information message
// @Tags hello
// @Accept json
// @Produce json
// @Param name query string true "Name"
// @Success 200 {object} map[string]string
// @Router /hello/info [get]
func (h *Hello) Info(c *ada.Context) error {
	name := c.Request.URL.Query().Get("name")
	return c.
		SetStatus(http.StatusOK).
		SetHeader("X-Custom-Header", "value").
		SendJSON(
			map[string]string{
				"message": "Hello, " + name + "!",
			},
		)
}
