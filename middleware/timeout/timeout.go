package timeout

import (
	"context"
	"net/http"
	"time"
)

// Middleware is a timeout middleware that cancels ctx after a given timeout.
//   - Control timeout by yourself in the error handler.
//   - If timeout <= 0, the middleware is a no-op.
func Middleware(timeout time.Duration) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if timeout <= 0 {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
