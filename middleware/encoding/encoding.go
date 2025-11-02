package encoding

import (
	"compress/gzip"
	"net/http"
	"strings"
)

type Config struct {
	Disabled bool `cfg:"disabled"`
	// Encoding support [gzip], default is gzip.
	Encoding []string `cfg:"encoding"`
}

func Middleware(opts ...Option) func(next http.Handler) http.Handler {
	var opt option
	for _, o := range opts {
		o(&opt)
	}

	if len(opt.Config.Encoding) == 0 {
		opt.Config.Encoding = []string{"gzip"}
	}

	for i := range opt.Config.Encoding {
		opt.Config.Encoding[i] = strings.ToLower(opt.Config.Encoding[i])
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opt.Config.Disabled {
				next.ServeHTTP(w, r)
				return
			}

			ae := r.Header.Get("Accept-Encoding")
			if ae == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Find the first supported encoding that the client accepts
			var selectedEncoding string
			for _, enc := range opt.Config.Encoding {
				if strings.Contains(ae, enc) {
					selectedEncoding = enc
					break
				}
			}

			// If no supported encoding is accepted by client
			if selectedEncoding == "" {
				next.ServeHTTP(w, r)
				return
			}

			switch selectedEncoding {
			case "gzip":
				// Create gzip writer from pool
				gz := gzipWriterPool.Get().(*gzip.Writer)
				defer gzipWriterPool.Put(gz)
				gz.Reset(w)
				defer gz.Close()

				// Wrap response writer
				gzw := &gzipResponseWriter{
					ResponseWriter: w,
					Writer:         gz,
				}

				// Set content encoding header
				w.Header().Set("Content-Encoding", selectedEncoding)
				w.Header().Del("Content-Length")

				next.ServeHTTP(gzw, r)
			default:
				// Unsupported encoding
				next.ServeHTTP(w, r)
				return
			}

		})
	}
}

// ////////////////////////////////////////////////////////////////////

type option struct {
	Config Config
}

type Option func(*option)

func WithConfig(cfg Config) Option {
	return func(o *option) {
		o.Config = cfg
	}
}
