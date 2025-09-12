package timeout

import (
	"context"
	"net/http"
	"time"
)

// Based in chi's timeout middleware

// Timeout is a middleware that cancels ctx after a given timeout.
//   - Return a 504 Gateway Timeout error to the client.
//   - If timeout <= 0, the middleware is a no-op.
func Timeout(timeout time.Duration) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if timeout <= 0 {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer func() {
				cancel()

				if ctx.Err() == context.DeadlineExceeded {
					w.WriteHeader(http.StatusGatewayTimeout)
				}
			}()

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
