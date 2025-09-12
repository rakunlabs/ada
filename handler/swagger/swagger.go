package swagger

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger/v2"
	"github.com/swaggo/swag"
)

var DefaultInfoInstanceName = "swagger"

func Handler(opts ...Option) func(w http.ResponseWriter, r *http.Request) {
	o := &option{
		InfoInstanceName: DefaultInfoInstanceName,
	}
	for _, opt := range opts {
		opt(o)
	}

	spec, _ := swag.GetSwagger(o.InfoInstanceName).(*swag.Spec)
	if spec != nil {
		if o.Version != nil {
			spec.Version = *o.Version
		}

		if o.Host != nil {
			spec.Host = *o.Host
		}

		if o.BasePath != nil {
			spec.BasePath = *o.BasePath
		}

		if o.Title != nil {
			spec.Title = *o.Title
		}

		if o.Description != nil {
			spec.Description = *o.Description
		}

		if o.Schemes != nil {
			spec.Schemes = o.Schemes
		}
	}

	return httpSwagger.Handler(o.ConfigFns...)
}

type option struct {
	ConfigFns []func(*httpSwagger.Config)

	Version          *string
	Host             *string
	BasePath         *string
	Title            *string
	Description      *string
	Schemes          []string
	InfoInstanceName string
}

type Option func(*option)

func WithConfigFns(fns ...func(*httpSwagger.Config)) Option {
	return func(o *option) {
		o.ConfigFns = append(o.ConfigFns, fns...)
	}
}

// WithInfoInstanceName sets the name of the swagger instance to be used.
//
// The default name is "swagger".
func WithInfoInstanceName(infoInstanceName string) Option {
	return func(opts *option) {
		opts.InfoInstanceName = infoInstanceName
	}
}

// WithVersion sets the version of the API.
func WithVersion(version string) Option {
	return func(opts *option) {
		opts.Version = &version
	}
}

// WithHost sets the host of the API.
func WithHost(host string) Option {
	return func(opts *option) {
		opts.Host = &host
	}
}

// WithBasePath sets the base path of the API.
func WithBasePath(basePath string) Option {
	return func(opts *option) {
		opts.BasePath = &basePath
	}
}

// WithSchemes sets the schemes of the API.
func WithSchemes(schemes ...string) Option {
	return func(opts *option) {
		opts.Schemes = schemes
	}
}

// WithTitle sets the title of the API.
func WithTitle(title string) Option {
	return func(opts *option) {
		opts.Title = &title
	}
}

// WithDescription sets the description of the API.
func WithDescription(description string) Option {
	return func(opts *option) {
		opts.Description = &description
	}
}
