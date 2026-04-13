package pipeline

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rakunlabs/ada"
)

// curl -v http://localhost:8080 - should include the X-My-Middleware header
// curl -v -X POST http://localhost:8080/switch - toggles the middleware on/off

func Run(ctx context.Context) error {
	server, err := ada.NewWithFunc(ctx, func(ctx context.Context, mux *ada.Mux) error {
		// SLOT example
		myMiddleware := ada.NewSlot(MyMiddleware)

		mux.GET("/", OKHandler, myMiddleware.Middleware())
		mux.POST("/switch", func(w http.ResponseWriter, r *http.Request) {
			if myMiddleware.Enabled() {
				myMiddleware.Disable()
				fmt.Fprintln(w, "Middleware disabled")
			} else {
				myMiddleware.Enable()
				fmt.Fprintln(w, "Middleware enabled")
			}
		})

		// PIPELINE example
		stack := ada.NewPipeline()
		first := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-First-Middleware", "true")
				next.ServeHTTP(w, r)
			})
		}

		stack.Set("first", first)
		stack.Set("second", func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Second-Middleware", "true")
				next.ServeHTTP(w, r)
			})
		})

		mux.GET("/pipeline", OKHandler, stack.Middleware())

		mux.POST("/pipeline/switch", func(w http.ResponseWriter, r *http.Request) {
			if stack.Has("first") {
				stack.Remove("first")
				fmt.Fprintln(w, "First middleware disabled")
			} else {
				stack.Set("first", first)
				fmt.Fprintln(w, "First middleware enabled")
			}
		})

		return nil
	})
	if err != nil {
		return err
	}

	return server.StartWithContext(ctx, ":8080")
}

func MyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-My-Middleware", "true")

		next.ServeHTTP(w, r)
	})
}

func OKHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}
