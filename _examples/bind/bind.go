package bind

import (
	"context"
	"net/http"

	"github.com/rakunlabs/ada"

	mcors "github.com/rakunlabs/ada/middleware/cors"
	mlog "github.com/rakunlabs/ada/middleware/log"
	mrecover "github.com/rakunlabs/ada/middleware/recover"
	mrequestid "github.com/rakunlabs/ada/middleware/requestid"
	mserver "github.com/rakunlabs/ada/middleware/server"
	mtelemetry "github.com/rakunlabs/ada/middleware/telemetry"
)

func Run(ctx context.Context) error {
	server, err := ada.NewWithFunc(ctx, func(ctx context.Context, mux *ada.Mux) error {
		mux.Use(
			mrecover.Middleware(),
			mserver.Middleware("bind-example"),
			mrequestid.Middleware(),
			mlog.Middleware(),
			mcors.Middleware(),
			mtelemetry.Middleware(),
		)
		mux.POST("/bind/{name}", mux.Wrap(func(c *ada.Context) error {
			var req struct {
				Name string `param:"name"`
				ID   int    `json:"id"`
			}
			if err := c.Bind(&req); err != nil {
				return c.SetStatus(http.StatusBadRequest).Err(err)
			}

			return c.SendJSON(map[string]any{
				"message": "Hello, " + req.Name,
				"id":      req.ID,
			})
		}))

		return nil
	})
	if err != nil {
		return err
	}

	return server.StartWithContext(ctx, ":8080")
}
