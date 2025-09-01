package requestid

import (
	"net/http"

	"github.com/oklog/ulid/v2"
)

const (
	HeaderXRequestID = "X-Request-Id"
)

type RequestID struct {
	Generate func() string
}

func New(opts ...Option) *RequestID {
	o := &option{}

	for _, opt := range opts {
		opt(o)
	}

	if o.Generate == nil {
		o.Generate = func() string {
			return ulid.Make().String()
		}
	}

	return &RequestID{
		Generate: o.Generate,
	}
}

func Middleware(opts ...Option) func(next http.Handler) http.Handler {
	return New(opts...).Middleware
}

func (re *RequestID) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate a new request ID or retrieve it from the context
		requestID := r.Header.Get(HeaderXRequestID)
		if requestID == "" {
			requestID = re.Generate()
			r.Header.Set(HeaderXRequestID, requestID)
		}

		// Set the request ID in the response header
		w.Header().Set(HeaderXRequestID, requestID)

		next.ServeHTTP(w, r)
	})
}

// //////////////////////////////////////////////////////////////

type option struct {
	Generate func() string
}

type Option func(*option)

func WithGenerateRequestID(fn func() string) Option {
	return func(o *option) {
		o.Generate = fn
	}
}
