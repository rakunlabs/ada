package ada

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

type option struct {
	Logger          Logger
	ShutdownTimeout time.Duration
}

type Option func(*option)

func getOption(opt option, opts ...Option) option {
	for _, o := range opts {
		o(&opt)
	}

	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}

	return opt
}

func WithLogger(logger Logger) Option {
	return func(opt *option) {
		opt.Logger = logger
	}
}

// WithShutdownTimeout sets the shutdown timeout, default is 10 seconds.
func WithShutdownTimeout(timeout time.Duration) Option {
	return func(opt *option) {
		opt.ShutdownTimeout = timeout
	}
}

type optionStart struct {
	Network           string
	Context           context.Context
	BaseContext       context.Context
	HTTPServerFunc    func(*http.Server) *http.Server
	ReadHeaderTimeout time.Duration
}

type OptionStart func(*optionStart)

func getOptionStart(opt optionStart, opts ...OptionStart) optionStart {
	for _, o := range opts {
		o(&opt)
	}

	if opt.Network == "" {
		opt.Network = "tcp"
	}

	if opt.HTTPServerFunc == nil {
		opt.HTTPServerFunc = func(s *http.Server) *http.Server {
			return s
		}
	}

	if opt.ReadHeaderTimeout == 0 {
		opt.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}

	return opt
}

// WithNetwork sets the network, default is "tcp".
func WithNetwork(network string) OptionStart {
	return func(opt *optionStart) {
		opt.Network = network
	}
}

// WithBaseContext sets the base context, default is context.Background().
//   - Default is context.Background().
func WithBaseContext(ctx context.Context) OptionStart {
	return func(opt *optionStart) {
		opt.BaseContext = ctx
	}
}

// WithContext sets the context, usable for stopping the server.
//   - Same as StartWithContext's ctx
func WithContext(ctx context.Context) OptionStart {
	return func(opt *optionStart) {
		opt.Context = ctx
	}
}

func WithHTTPServerFunc(fn func(server *http.Server) *http.Server) OptionStart {
	return func(opt *optionStart) {
		opt.HTTPServerFunc = fn
	}
}

// WithReadHeaderTimeout sets the ReadHeaderTimeout for the http.Server.
//   - Default is DefaultReadHeaderTimeout (10 seconds).
//   - A value of 0 selects the default, it does NOT disable the timeout.
//     There is deliberately no opt-out through this option; to run with an
//     unbounded header read, set ReadHeaderTimeout to 0 on the server passed
//     to WithHTTPServerFunc.
func WithReadHeaderTimeout(d time.Duration) OptionStart {
	return func(opt *optionStart) {
		opt.ReadHeaderTimeout = d
	}
}
