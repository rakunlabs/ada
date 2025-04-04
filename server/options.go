package server

import (
	"log/slog"

	"github.com/rakunlabs/logi/logadapter"
)

type option struct {
	Logger logadapter.Adapter
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

func WithLogger(logger logadapter.Adapter) Option {
	return func(opt *option) {
		opt.Logger = logger
	}
}
