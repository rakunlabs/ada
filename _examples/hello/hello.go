package hello

import (
	"context"
	"io"
	"net/http"

	"github.com/rakunlabs/ada"
)

func Run(ctx context.Context) error {
	server, err := ada.NewWithFunc(ctx, func(ctx context.Context, mux *ada.Mux) error {
		helloHandler := &Hello{}
		mux.POST("/hello", helloHandler.SayHello)
		mux.GET("/", helloHandler.Info)

		return nil
	})
	if err != nil {
		return err
	}

	return server.StartWithContext(ctx, ":8080")
}

type Hello struct{}

func (h *Hello) SayHello(w http.ResponseWriter, r *http.Request) {
	v, _ := io.ReadAll(r.Body)

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hello, " + string(v)))
}

func (h *Hello) Info(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hello, Info!"))
}
