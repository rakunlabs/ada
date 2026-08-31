package bind

import "fmt"

var (
	DefaultMultipartFormMaxMemory = int64(32 << 20) // 32MB
	DefaultBodyLimit              = int64(1 << 20)  // 1 MiB total request body
	DefaultQuerySeparator         = ","
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
// before being spooled to disk. It does not set the total request size; use
// WithBodyLimit for that. The default is 32 MiB (32 << 20 bytes).
func WithMultipartFormMaxMemory(maxMemory int64) Option {
	return func(o *option) {
		if maxMemory < 0 {
			o.setError("multipart form max memory cannot be negative")
			return
		}
		o.MultipartFormMaxMemory = maxMemory
	}
}

// WithBodyLimit sets the maximum total request body size for JSON, XML,
// URL-encoded form, and multipart requests. The secure default is 1 MiB.
//
// The default intentionally limits bodies that older versions accepted without
// a package-level cap. Set limit to 0 to restore that compatibility only when an
// equivalent limit is enforced upstream; zero disables this protection.
func WithBodyLimit(limit int64) Option {
	return func(o *option) {
		if limit < 0 {
			o.setError("body limit cannot be negative")
			return
		}
		o.BodyLimit = limit
	}
}

// WithQuerySeparator sets the separator for query parameters when binding slices
//   - default is "," -> ?ids=1,2,3
//   - set to "" to disable splitting
func WithQuerySeparator(sep string) Option {
	return func(o *option) {
		o.QuerySeparator = sep
	}
}
