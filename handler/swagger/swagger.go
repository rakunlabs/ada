package swagger

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/swaggo/swag"
)

var DefaultInfoInstanceName = "swagger"

// dist holds only the Swagger UI assets referenced by the index page.
// Source maps and unused bundles are intentionally left out to keep binaries small.
//
//go:embed dist/*
var dist embed.FS

var distFS, _ = fs.Sub(dist, "dist")

var indexTemplate = template.Must(template.New("swagger_index.html").Parse(indexTempl))

type SwaggerLayout string

const (
	BaseLayout       SwaggerLayout = "BaseLayout"
	StandaloneLayout SwaggerLayout = "StandaloneLayout"
)

type ModelsExpandDepthType int

const (
	ShowModel ModelsExpandDepthType = 1
	HideModel ModelsExpandDepthType = -1
)

// Config holds Swagger UI page settings.
type Config struct {
	// URL pointing to API definition. Default is `doc.json`.
	URL                      string
	DocExpansion             string
	DomID                    string
	BeforeScript             template.JS
	AfterScript              template.JS
	Plugins                  []template.JS
	UIConfig                 map[template.JS]template.JS
	DeepLinking              bool
	PersistAuthorization     bool
	Layout                   SwaggerLayout
	DefaultModelsExpandDepth ModelsExpandDepthType
}

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

	config := &Config{
		URL:                      "doc.json",
		DocExpansion:             "list",
		DomID:                    "swagger-ui",
		DeepLinking:              true,
		Layout:                   StandaloneLayout,
		DefaultModelsExpandDepth: ShowModel,
	}
	for _, fn := range o.ConfigFns {
		fn(config)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)

			return
		}

		name := path.Base(r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/") {
			name = ""
		}

		switch name {
		case "":
			http.Redirect(w, r, r.URL.Path+"index.html", http.StatusMovedPermanently)
		case "index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = indexTemplate.Execute(w, config)
		case "doc.json":
			doc, err := swag.ReadDoc(o.InfoInstanceName)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

				return
			}

			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(doc))
		default:
			if info, err := fs.Stat(distFS, name); err != nil || info.IsDir() {
				http.NotFound(w, r)

				return
			}

			http.ServeFileFS(w, r, distFS, name)
		}
	}
}

type option struct {
	ConfigFns []func(*Config)

	Version          *string
	Host             *string
	BasePath         *string
	Title            *string
	Description      *string
	Schemes          []string
	InfoInstanceName string
}

type Option func(*option)

// WithConfigFns customizes the Swagger UI page.
func WithConfigFns(fns ...func(*Config)) Option {
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
