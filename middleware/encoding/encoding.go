// Package encoding compresses HTTP responses with zstd, brotli or gzip
// according to the client's Accept-Encoding header.
package encoding

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const (
	EncodingZstd   = "zstd"
	EncodingBrotli = "br"
	EncodingGzip   = "gzip"
)

// DefaultMinLength is the default minimum body size in bytes worth compressing.
const DefaultMinLength = 1024

var defaultEncodings = []string{EncodingZstd, EncodingBrotli, EncodingGzip}

// DefaultExcludedContentTypes lists already compressed formats that are not
// worth compressing again. Compressible images (SVG, BMP, ICO) are still
// compressed while this default list is in use.
var DefaultExcludedContentTypes = []string{
	"image/*",
	"video/*",
	"audio/*",
	"font/woff",
	"font/woff2",
	"application/zip",
	"application/gzip",
	"application/x-gzip",
	"application/zstd",
	"application/x-7z-compressed",
	"application/x-rar-compressed",
	"application/octet-stream",
	"application/grpc",
}

// compressibleImages are image types that still benefit from compression.
var compressibleImages = []string{"image/svg+xml", "image/bmp", "image/x-icon", "image/vnd.microsoft.icon"}

type Config struct {
	// Disabled bypasses negotiation and compression. Other configuration is
	// still validated during middleware construction.
	Disabled bool `cfg:"disabled"`
	// Encoding lists enabled response encodings in server preference order.
	// When the client accepts several with the same quality, the first one
	// wins. Supported values are "zstd", "br" and "gzip". Values are trimmed
	// and case-insensitive; empty, duplicate or unsupported values panic during
	// middleware construction. The default is []string{"zstd", "br", "gzip"}.
	Encoding []string `cfg:"encoding"`
	// MinLength is the minimum response size in bytes to compress. Up to
	// MinLength bytes are buffered to decide; a Flush ends buffering early.
	// Set 1 to compress every non-empty body. Negative values panic. The
	// default is DefaultMinLength.
	MinLength int `cfg:"min_length"`
	// ExcludedContentTypes are never compressed. "type/*" wildcards are
	// supported and parameters such as charset are ignored. A nil value uses
	// DefaultExcludedContentTypes; an empty non-nil slice excludes nothing.
	ExcludedContentTypes []string `cfg:"excluded_content_types"`
	// IncludedContentTypes, when set, restricts compression to these content
	// types and ExcludedContentTypes is ignored.
	IncludedContentTypes []string `cfg:"included_content_types"`

	// GzipLevel defaults to gzip.DefaultCompression; valid range is -2..9.
	GzipLevel *int `cfg:"gzip_level"`
	// BrotliLevel defaults to 4; valid range is 0..11.
	BrotliLevel *int `cfg:"brotli_level"`
	// ZstdLevel defaults to the encoder's default speed; valid range is 1..22.
	ZstdLevel *int `cfg:"zstd_level"`
}

// Middleware constructs response encoding middleware. It panics when Config
// contains an invalid or unsupported value.
func Middleware(opts ...Option) func(next http.Handler) http.Handler {
	var opt option
	for _, o := range opts {
		o(&opt)
	}

	cfg := opt.Config

	encodings := slices.Clone(cfg.Encoding)
	if len(encodings) == 0 {
		encodings = slices.Clone(defaultEncodings)
	}

	pools := make(map[string]*encoderPool, len(encodings))
	for i, configured := range encodings {
		enc := strings.ToLower(strings.TrimSpace(configured))
		if enc == "" {
			panic("encoding: configured encoding must not be empty")
		}
		if _, ok := pools[enc]; ok {
			panic(fmt.Sprintf("encoding: duplicate configured encoding %q", enc))
		}

		var (
			pool *encoderPool
			err  error
		)
		switch enc {
		case EncodingGzip:
			pool, err = newGzipPool(cfg.GzipLevel)
		case EncodingBrotli:
			pool, err = newBrotliPool(cfg.BrotliLevel)
		case EncodingZstd:
			pool, err = newZstdPool(cfg.ZstdLevel)
		default:
			panic(fmt.Sprintf("encoding: unsupported configured encoding %q (supported: zstd, br, gzip)", enc))
		}
		if err != nil {
			panic(fmt.Sprintf("encoding: %v", err))
		}

		pools[enc] = pool
		encodings[i] = enc
	}

	minLength := cfg.MinLength
	if minLength < 0 {
		panic("encoding: MinLength must not be negative")
	}
	if minLength == 0 {
		minLength = DefaultMinLength
	}

	excluded := cfg.ExcludedContentTypes
	if excluded == nil {
		excluded = DefaultExcludedContentTypes
	}

	filter := &contentTypeFilter{
		excluded: normalizeTypes(excluded),
		included: normalizeTypes(cfg.IncludedContentTypes),
		// The default image/* exclusion must not drop compressible images.
		allowImages: cfg.ExcludedContentTypes == nil,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Disabled {
				next.ServeHTTP(w, r)
				return
			}

			// Upgrades (WebSocket) need the raw ResponseWriter so the handler
			// can hijack the connection.
			if isUpgrade(r) {
				next.ServeHTTP(w, r)
				return
			}

			addVary(w.Header(), "Accept-Encoding")

			acceptEncoding := r.Header.Values("Accept-Encoding")
			qualities := parseEncodingQualities(acceptEncoding)

			selectedEncoding, selectedQuality := "", float64(0)
			for _, enc := range encodings {
				if quality := encodingQuality(qualities, enc); quality > selectedQuality {
					selectedEncoding, selectedQuality = enc, quality
				}
			}

			if selectedEncoding == "" {
				if !identityAccepted(qualities) {
					http.Error(w, "no acceptable content encoding", http.StatusNotAcceptable)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			if r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			cw := &responseWriter{
				ResponseWriter: w,
				encoding:       selectedEncoding,
				pool:           pools[selectedEncoding],
				minLength:      minLength,
				filter:         filter,
			}
			defer cw.close()

			next.ServeHTTP(cw, r)
		})
	}
}

func isUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, value := range r.Header.Values("Connection") {
		for token := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func encodingQuality(qualities map[string]float64, encoding string) float64 {
	if quality, ok := qualities[encoding]; ok {
		return quality
	}
	return qualities["*"]
}

func identityAccepted(qualities map[string]float64) bool {
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

type contentTypeFilter struct {
	excluded    []string
	included    []string
	allowImages bool
}

func normalizeTypes(types []string) []string {
	out := make([]string, 0, len(types))
	for _, t := range types {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func matchType(pattern, contentType string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "/*"); ok {
		return strings.HasPrefix(contentType, prefix+"/")
	}
	return pattern == contentType
}

func (f *contentTypeFilter) allowed(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))

	if len(f.included) > 0 {
		return slices.ContainsFunc(f.included, func(p string) bool { return matchType(p, mediaType) })
	}

	if f.allowImages && slices.Contains(compressibleImages, mediaType) {
		return true
	}

	return !slices.ContainsFunc(f.excluded, func(p string) bool { return matchType(p, mediaType) })
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
