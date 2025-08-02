package ada

import (
	"log/slog"
	"time"
)

type option struct {
	Logger          Logger
	Network         string
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
	if opt.Network == "" {
		opt.Network = "tcp"
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

// WithNetwork sets the network, default is "tcp".
func WithNetwork(network string) Option {
	return func(opt *option) {
		opt.Network = network
	}
}
