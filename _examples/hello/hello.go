package hello

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/logi"

	mcors "github.com/rakunlabs/ada/middleware/cors"
	mencoding "github.com/rakunlabs/ada/middleware/encoding"
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
			mencoding.Middleware(),
		)
		mux.POST("/hello", helloHandler.SayHello, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logi.Ctx(r.Context()).Info("before saying hello 1")
				next.ServeHTTP(w, r)
				logi.Ctx(r.Context()).Info("after saying hello 1")
			})
		},
			func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					logi.Ctx(r.Context()).Info("before saying hello 2")
					next.ServeHTTP(w, r)
					logi.Ctx(r.Context()).Info("after saying hello 2")
				})
			},
		)
		mux.GET("/", helloHandler.Main)
		mux.GET("/hello/info", helloHandler.Info)
		mux.GET("/hello/zip", helloHandler.Zip)
		mux.GET("/hello/file", helloHandler.File)

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

func (h *Hello) Zip(c *ada.Context) error {
	return c.SendZip("files.zip", map[string]io.Reader{
		"test.txt": strings.NewReader("Hello, World!"),
		"data.csv": strings.NewReader("name,age\nAlice,30\nBob,25"),
	})
}

func (h *Hello) File(c *ada.Context) error {
	return c.SendFile("greeting.txt", strings.NewReader("Hello, World!"))
}

func (h *Hello) SayHello(w http.ResponseWriter, r *http.Request) {
	v, _ := io.ReadAll(r.Body)

	logi.Ctx(r.Context()).Info("saying hello")

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hello, " + string(v)))
}

func (h *Hello) Main(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Main!"))
}
