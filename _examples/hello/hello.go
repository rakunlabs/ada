package hello

import (
	"context"
	"io"
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
		helloHandler := &Hello{}

		mux.Use(
			mrecover.Middleware(),
			mserver.Middleware("MyServer"),
			mrequestid.Middleware(),
			mlog.Middleware(),
			mcors.Middleware(),
			mtelemetry.Middleware(),
		)
		mux.POST("/hello", helloHandler.SayHello)
		mux.GET("/", helloHandler.Main)
		mux.GET("/hello/info", mux.Wrap(helloHandler.Info))

		return nil
	})
	if err != nil {
		return err
	}

	return server.StartWithContext(ctx, ":8080")
}

type Hello struct{}

func (h *Hello) Info(c *ada.Context) error {
	return c.
		SetStatus(http.StatusOK).
		SetHeader("X-Custom-Header", "value").
		SendJSON(
			map[string]string{
				"message": "Info!",
			},
		)
}

func (h *Hello) SayHello(w http.ResponseWriter, r *http.Request) {
	v, _ := io.ReadAll(r.Body)

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hello, " + string(v)))
}

func (h *Hello) Main(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Main!"))
}
