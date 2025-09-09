package bind

var (
	DefaultMultipartFormMaxMemory = int64(32 << 20) // 32MB
	DefaultQuerySeparator         = ","
)

type option struct {
	MultipartFormMaxMemory int64
	QuerySeparator         string
}

func applyOptions(opts ...Option) *option {
	o := &option{
		MultipartFormMaxMemory: DefaultMultipartFormMaxMemory,
		QuerySeparator:         DefaultQuerySeparator,
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// Option defines a function type for setting options.
type Option func(*option)

// WithMultipartFormMaxMemory sets the maximum memory for parsing multipart forms
//   - default is 32MB (32 << 20 bytes)
func WithMultipartFormMaxMemory(maxMemory int64) Option {
	return func(o *option) {
		o.MultipartFormMaxMemory = maxMemory
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
