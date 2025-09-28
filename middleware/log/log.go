package log

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/rakunlabs/logi"
)

var trueClientIP = http.CanonicalHeaderKey("True-Client-IP")
var xForwardedFor = http.CanonicalHeaderKey("X-Forwarded-For")
var xRealIP = http.CanonicalHeaderKey("X-Real-IP")

// Logger is a middleware that logs HTTP requests and additional information to context.
type Logger struct {
	Skipper  func(r *http.Request) bool
	PreFunc  func(r *http.Request) *http.Request
	PostFunc func(r *http.Request, v *Response)
}

// Response contains extracted values from logger.
type Response struct {
	// StartTime is time recorded before next middleware/handler is executed.
	StartTime time.Time
	// Latency is duration it took to execute rest of the handler chain (next(c) call).
	Latency time.Duration
	// Status is response status code. Then handler returns an echo.HTTPError then code from there.
	Status int
	// ResponseSize is response content length value. Note: when used with Gzip middleware this value may not be always correct.
	ResponseSize int64
}

func (l *Logger) Middleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip logging if skipper function is provided and returns true
			if l.Skipper != nil && l.Skipper(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Record start time
			start := time.Now()

			if l.PreFunc != nil {
				r = l.PreFunc(r)
			}

			// Execute the next handler
			m := httpsnoop.CaptureMetrics(next, w, r)

			// Calculate latency
			latency := time.Since(start)

			// Extract request values based on configuration
			values := &Response{
				StartTime: start,
				Latency:   latency,
			}

			// Extract status if enabled
			values.Status = m.Code

			// Extract response size if enabled
			values.ResponseSize = m.Written

			// Call the custom logging function if provided
			if l.PostFunc != nil {
				l.PostFunc(r, values)
			}
		})
	}
}

func New(opts ...Option) *Logger {
	o := option{
		Logger: Logger{
			PreFunc: func(r *http.Request) *http.Request {
				user := r.Header.Get("X-User")
				requestID := r.Header.Get("X-Request-ID")
				userAgent := userAgent(r)

				slogAttrs := make([]any, 0, 3)
				if requestID != "" {
					slogAttrs = append(slogAttrs, slog.String("request_id", requestID))
				}
				if user != "" {
					slogAttrs = append(slogAttrs, slog.String("user", user))
				}
				if userAgent != "" {
					slogAttrs = append(slogAttrs, slog.String("user_agent", userAgent))
				}

				return r.WithContext(logi.WithContext(r.Context(), slog.With(slogAttrs...)))
			},
			PostFunc: func(r *http.Request, v *Response) {
				slog.Debug("request",
					slog.String("user", r.Header.Get("X-User")),
					slog.String("route", r.Pattern),
					slog.String("request_id", r.Header.Get("X-Request-ID")),
					slog.String("remote_ip", realIP(r)),
					slog.String("host", r.Host),
					slog.String("method", r.Method),
					slog.String("uri", r.RequestURI),
					slog.String("user_agent", userAgent(r)),
					slog.Int("status", v.Status),
					slog.Int64("latency", v.Latency.Nanoseconds()),
					slog.String("latency_human", v.Latency.String()),
					slog.String("bytes_in", r.Header.Get("Content-Length")),
					slog.Int64("bytes_out", v.ResponseSize),
				)
			},
		},
	}

	for _, opt := range opts {
		opt(&o)
	}

	return &o.Logger
}

func Middleware(opts ...Option) func(next http.Handler) http.Handler {
	return New(opts...).Middleware()
}

func realIP(r *http.Request) (ip string) {
	defer func() {
		if ip == "" {
			ip = r.RemoteAddr
		}
	}()

	if tcip := r.Header.Get(trueClientIP); tcip != "" {
		ip = tcip
	} else if xrip := r.Header.Get(xRealIP); xrip != "" {
		ip = xrip
	} else if xff := r.Header.Get(xForwardedFor); xff != "" {
		ip, _, _ = strings.Cut(xff, ",")
	}
	if ip == "" || net.ParseIP(ip) == nil {
		return ""
	}

	return ip
}

func userAgent(r *http.Request) string {
	// get first part of user-agent before space
	if ua := r.Header.Get("User-Agent"); ua != "" {
		if i := strings.Index(ua, " "); i != -1 {
			return ua[:i]
		}

		return ua
	}

	return ""
}

// //////////////////////////////////////////////////////

type option struct {
	Logger Logger
}

type Option func(*option)

// WithLogger sets a custom Logger directly.
func WithLogger(l Logger) Option {
	return func(o *option) {
		o.Logger = l
	}
}

// WithSkipper sets a function to skip middleware.
//   - Default is nil.
func WithSkipper(skipper func(r *http.Request) bool) Option {
	return func(o *option) {
		o.Logger.Skipper = skipper
	}
}

// WithPostFunc sets a function which is called after the request is processed.
//   - This will override the default PostFunc which logs some useful information.
func WithPostFunc(f func(r *http.Request, v *Response)) Option {
	return func(o *option) {
		o.Logger.PostFunc = f
	}
}

// WithPreFunc sets a function which is called before the request is processed.
//   - This will override the default PreFunc which adds some useful information to the context.
func WithPreFunc(f func(r *http.Request) *http.Request) Option {
	return func(o *option) {
		o.Logger.PreFunc = f
	}
}
