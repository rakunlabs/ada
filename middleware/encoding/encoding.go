package encoding

import (
	"compress/gzip"
	"net/http"
	"strconv"
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

			addVary(w.Header(), "Accept-Encoding")

			selectedEncoding, selectedQuality := "", float64(0)
			for _, enc := range opt.Config.Encoding {
				if quality := encodingQuality(r.Header.Values("Accept-Encoding"), enc); quality > selectedQuality {
					selectedEncoding, selectedQuality = enc, quality
				}
			}

			if selectedEncoding == "" {
				if !identityAccepted(r.Header.Values("Accept-Encoding")) {
					http.Error(w, "no acceptable content encoding", http.StatusNotAcceptable)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			switch selectedEncoding {
			case "gzip":
				gz := gzipWriterPool.Get().(*gzip.Writer)
				gzw := &gzipResponseWriter{
					ResponseWriter: w,
					writer:         gz,
					requestMethod:  r.Method,
				}
				defer func() {
					gzw.close()
					gzipWriterPool.Put(gz)
				}()
				next.ServeHTTP(gzw, r)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}

func encodingQuality(headerValues []string, encoding string) float64 {
	qualities := parseEncodingQualities(headerValues)
	if quality, ok := qualities[strings.ToLower(encoding)]; ok {
		return quality
	}
	return qualities["*"]
}

func identityAccepted(headerValues []string) bool {
	qualities := parseEncodingQualities(headerValues)
	if quality, ok := qualities["identity"]; ok {
		return quality > 0
	}
	if quality, ok := qualities["*"]; ok {
		return quality > 0
	}

	// Identity is acceptable by default even when the client lists other
	// encodings but says nothing about identity.
	return true
}

func parseEncodingQualities(headerValues []string) map[string]float64 {
	qualities := make(map[string]float64)
	for _, headerValue := range headerValues {
		for token := range strings.SplitSeq(headerValue, ",") {
			parts := strings.Split(token, ";")
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			if name == "" {
				continue
			}

			quality := float64(1)
			for _, parameter := range parts[1:] {
				key, value, ok := strings.Cut(parameter, "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
					continue
				}
				parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err != nil || parsed < 0 || parsed > 1 {
					quality = 0
				} else {
					quality = parsed
				}
			}
			qualities[name] = quality
		}
	}

	return qualities
}

func addVary(header http.Header, value string) {
	values := header.Values("Vary")
	for _, existing := range values {
		for token := range strings.SplitSeq(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(token), value) || strings.TrimSpace(token) == "*" {
				return
			}
		}
	}

	if len(values) == 0 {
		header.Set("Vary", value)
		return
	}
	header.Set("Vary", strings.Join(values, ", ")+", "+value)
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
