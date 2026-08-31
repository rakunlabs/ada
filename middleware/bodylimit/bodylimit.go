// Package bodylimit provides an HTTP middleware that caps the size of a
// request body.
//
// The limit is enforced twice, because a Content-Length header is a claim by
// the client and not a fact:
//
//   - A declared Content-Length larger than the limit is rejected with 413
//     before the handler runs and before a single byte of the body is read.
//   - Every other request has its body replaced by http.MaxBytesReader, so a
//     chunked body, a missing Content-Length, or a Content-Length that
//     understates the real size is still caught while the handler reads.
//
// Typical usage:
//
//	server.Use(bodylimit.Middleware(1 << 20))
//
//	server.Use(bodylimit.Middleware(1<<20, bodylimit.WithSkipper(
//	    func(r *http.Request) bool {
//	        return strings.HasPrefix(r.URL.Path, "/upload/")
//	    },
//	)))
package bodylimit

import (
	"net/http"
	"strconv"
)

const (
	headerConnection  = "Connection"
	headerContentType = "Content-Type"
)

// Middleware returns a middleware limiting the request body to limit bytes.
//
// A request whose declared Content-Length exceeds limit is answered with 413
// Request Entity Too Large; next is not invoked and the body is never read.
// Any other request reaches next with r.Body wrapped in http.MaxBytesReader,
// so reading past limit bytes fails with *http.MaxBytesError and the handler
// decides how to report it. That is the standard library idiom: it also marks
// the request as too large so net/http stops draining the rest of the
// connection.
//
// Panics if limit <= 0. A non-positive limit would reject or break every
// request carrying a body, so it is always a configuration mistake and
// failing at construction is better than failing per request in production.
func Middleware(limit int64, opts ...Option) func(next http.Handler) http.Handler {
	if limit <= 0 {
		panic("bodylimit: limit must be greater than zero")
	}

	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	// The rejection body only depends on limit, so build it once.
	tooLarge := []byte(`{"error":"body_too_large","message":"request body exceeds limit of ` +
		strconv.FormatInt(limit, 10) + ` bytes"}`)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.skipper != nil && cfg.skipper(r) {
				next.ServeHTTP(w, r)

				return
			}

			// ContentLength is -1 when the length is unknown (chunked), so
			// this comparison only fires on an explicit, oversized claim.
			if r.ContentLength > limit {
				writeTooLarge(w, r, tooLarge)

				return
			}

			// net/http never hands a server handler a nil Body, but a
			// hand-built *http.Request can; guard so we never turn a
			// synthetic request into a nil dereference at read time.
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// writeTooLarge sends the 413 for the up-front Content-Length rejection.
//
// Connection handling: the client announced a body we have decided never to
// read, and it is very likely still streaming it. On HTTP/1.x we ask for the
// connection to be closed. This costs a reconnect, and is chosen anyway
// because:
//
//   - It matches what the read-time path already does. http.MaxBytesReader
//     calls the server's requestTooLarge hook, which sets Connection: close
//     and stops the drain, so both rejection paths behave the same way.
//   - Otherwise net/http drains the unread body to reuse the connection, and
//     for any body over 256 KiB it gives up and closes anyway. Draining bytes
//     we just refused is wasted bandwidth for an outcome that is usually the
//     same.
//
// On HTTP/2 the header is deliberately not set. Connection-specific headers
// are forbidden by RFC 9113 8.2.2, and Go's HTTP/2 server treats a handler
// setting Connection: close as a request for a graceful shutdown of the whole
// connection — that would send GOAWAY and tear down every other in-flight
// stream from that client. One oversized request must not do that; HTTP/2 has
// no connection-reuse problem here because the stream ends on its own.
func writeTooLarge(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.ProtoMajor == 1 {
		w.Header().Set(headerConnection, "close")
	}
	w.Header().Set(headerContentType, "application/json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_, _ = w.Write(body)
}

// //////////////////////////////////////////////////////////////

type config struct {
	skipper func(*http.Request) bool
}

type Option func(*config)

// WithSkipper skips the limit when fn returns true.
//   - Skipped requests reach the handler completely untouched: no rejection
//     and no wrapped body.
//   - Default is nil, meaning every request is limited. A nil fn clears a
//     previously set skipper.
func WithSkipper(fn func(*http.Request) bool) Option {
	return func(c *config) {
		c.skipper = fn
	}
}
