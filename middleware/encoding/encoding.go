package encoding

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

type Config struct {
	// Disabled bypasses negotiation and compression. Other configuration is
	// still validated during middleware construction.
	Disabled bool `cfg:"disabled"`
	// Encoding lists enabled response encodings. Only gzip is supported. Values
	// are trimmed and case-insensitive; empty, duplicate or unsupported values
	// panic during middleware construction. The default is []string{"gzip"}.
	Encoding []string `cfg:"encoding"`
}

// Middleware constructs response encoding middleware. It panics when Config
// contains an invalid or unsupported encoding.
func Middleware(opts ...Option) func(next http.Handler) http.Handler {
	var opt option
	for _, o := range opts {
		o(&opt)
	}

	cfg := opt.Config
	cfg.Encoding = slices.Clone(cfg.Encoding)
	if len(cfg.Encoding) == 0 {
		cfg.Encoding = []string{"gzip"}
	}

	seen := make(map[string]struct{}, len(cfg.Encoding))
	for i, configured := range cfg.Encoding {
		encoding := strings.ToLower(strings.TrimSpace(configured))
		if encoding == "" {
			panic("encoding: configured encoding must not be empty")
		}
		if _, ok := seen[encoding]; ok {
			panic(fmt.Sprintf("encoding: duplicate configured encoding %q", encoding))
		}
		if encoding != "gzip" {
			panic(fmt.Sprintf("encoding: unsupported configured encoding %q (supported: gzip)", encoding))
		}
		seen[encoding] = struct{}{}
		cfg.Encoding[i] = encoding
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Disabled {
				next.ServeHTTP(w, r)
				return
			}

			addVary(w.Header(), "Accept-Encoding")

			selectedEncoding, selectedQuality := "", float64(0)
			for _, enc := range cfg.Encoding {
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
				if quality == 0 {
					continue
				}
				parsed, ok := parseQuality(strings.TrimSpace(value))
				if !ok {
					quality = 0
				} else {
					quality = parsed
				}
			}
			if previous, exists := qualities[name]; !exists || quality < previous {
				qualities[name] = quality
			}
		}
	}

	return qualities
}

// parseQuality implements the qvalue grammar from RFC 9110 section 12.4.2.
func parseQuality(value string) (float64, bool) {
	if value == "0" || value == "1" {
		quality, _ := strconv.ParseFloat(value, 64)
		return quality, true
	}
	whole, fraction, ok := strings.Cut(value, ".")
	if !ok || len(fraction) > 3 || (whole != "0" && whole != "1") {
		return 0, false
	}
	for _, digit := range fraction {
		if digit < '0' || digit > '9' || whole == "1" && digit != '0' {
			return 0, false
		}
	}
	quality, err := strconv.ParseFloat(value, 64)
	return quality, err == nil
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
