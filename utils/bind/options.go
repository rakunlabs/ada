package bind

import "fmt"

var (
	// DefaultMultipartFormMaxMemory is the memory/disk threshold handed to
	// http.Request.ParseMultipartForm. It is NOT a size limit: it never
	// rejects a request, it only decides how much is held in memory before the
	// rest is spooled to temporary files. See WithMultipartFormMaxMemory.
	DefaultMultipartFormMaxMemory = int64(32 << 20) // 32 MiB

	// DefaultBodyLimit is the body limit used when no WithBodyLimit option is
	// given. It is 0 — no limit.
	//
	// A limit enforced here can only ever cover requests that reach Bind, so it
	// gives no protection to a handler that reads req.Body itself while
	// silently rejecting bodies that every other part of the service accepts.
	// It also capped the total body below DefaultMultipartFormMaxMemory, making
	// that 32 MiB setting unreachable.
	//
	// Limit request bodies with the middleware/bodylimit middleware instead: it
	// wraps the body in http.MaxBytesReader for the whole request, so the same
	// limit applies to Bind and to direct req.Body readers, and it answers
	// 413 Content Too Large.
	DefaultBodyLimit = int64(0)

	// DefaultQuerySeparator is the separator used when no WithQuerySeparator
	// option is given. See WithQuerySeparator.
	DefaultQuerySeparator = ","
)

type option struct {
	MultipartFormMaxMemory int64
	BodyLimit              int64
	QuerySeparator         string
	err                    error
}

func applyOptions(opts ...Option) *option {
	o := &option{
		MultipartFormMaxMemory: DefaultMultipartFormMaxMemory,
		BodyLimit:              DefaultBodyLimit,
		QuerySeparator:         DefaultQuerySeparator,
	}

	for _, opt := range opts {
		if opt == nil {
			o.setError("option cannot be nil")
			continue
		}
		opt(o)
	}
	if o.MultipartFormMaxMemory < 0 {
		o.setError("multipart form max memory cannot be negative")
	}
	if o.BodyLimit < 0 {
		o.setError("body limit cannot be negative")
	}

	return o
}

// Option defines a function type for setting options.
type Option func(*option)

func (o *option) setError(message string) {
	if o.err == nil {
		o.err = fmt.Errorf("%s", message)
	}
}

// WithMultipartFormMaxMemory sets how much multipart file data is held in memory
// before being spooled to disk. The default is 32 MiB (32 << 20 bytes).
//
// This is a threshold, not a limit: a larger upload is not rejected, it is
// written to temporary files instead. Go reserves a further 10 MiB for the
// non-file parts, so the effective memory ceiling is about maxMemory + 10 MiB.
// A multipart endpoint left unbounded therefore exhausts disk rather than
// memory.
//
// To actually bound the request, use the middleware/bodylimit middleware, or
// WithBodyLimit for a single Bind call.
//
// The temporary files are removed after the handler returns; Bind also removes
// them itself when it was the code that parsed the form.
func WithMultipartFormMaxMemory(maxMemory int64) Option {
	return func(o *option) {
		if maxMemory < 0 {
			o.setError("multipart form max memory cannot be negative")
			return
		}
		o.MultipartFormMaxMemory = maxMemory
	}
}

// WithBodyLimit sets the maximum total request body size for the JSON, XML,
// URL-encoded form, and multipart requests handled by this Bind call. A limit
// of 0 — the default, see DefaultBodyLimit — disables the check.
//
// This is a per-call escape hatch for an endpoint that needs a tighter bound
// than the rest of the service. For a service-wide limit prefer the
// middleware/bodylimit middleware, which caps the body for the whole request
// rather than only the part Bind happens to read.
//
// Exceeding the limit returns an error wrapping ErrBodyTooLarge, which the ada
// error handler reports as 413 Content Too Large.
func WithBodyLimit(limit int64) Option {
	return func(o *option) {
		if limit < 0 {
			o.setError("body limit cannot be negative")
			return
		}
		o.BodyLimit = limit
	}
}

// WithQuerySeparator sets the separator for scalar-valued query slices. The
// default is ","; set sep to "" to disable splitting.
//
// Scalar fields receive the first raw parameter value. JSON-valued slices such
// as []json.RawMessage, []struct, and []map also preserve each repeated value
// as a whole. The option does not affect form, header, or URI binding.
//
//	Tags []string `query:"tags"`   // ?tags=a,b,c   -> ["a" "b" "c"]
//	Name string   `query:"name"`   // ?name=Doe,+John -> "Doe, John"
func WithQuerySeparator(sep string) Option {
	return func(o *option) {
		o.QuerySeparator = sep
	}
}
