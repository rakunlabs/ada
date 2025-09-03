package log

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/felixge/httpsnoop"
)

// Logger is based on echo's log middleware.

type Logger struct {
	Skipper       func(r *http.Request) bool
	LogValuesFunc func(r *http.Request, v *RequestLoggerValues)

	// LogLatency instructs logger to record duration it took to execute rest of the handler chain (next(c) call).
	LogLatency bool
	// LogProtocol instructs logger to extract request protocol (i.e. `HTTP/1.1` or `HTTP/2`)
	LogProtocol bool
	// LogRemoteIP instructs logger to extract request remote IP. See `echo.Context.RealIP()` for implementation details.
	LogRemoteIP bool
	// LogHost instructs logger to extract request host value (i.e. `example.com`)
	LogHost bool
	// LogMethod instructs logger to extract request method value (i.e. `GET` etc)
	LogMethod bool
	// LogURI instructs logger to extract request URI (i.e. `/list?lang=en&page=1`)
	LogURI bool
	// LogURIPath instructs logger to extract request URI path part (i.e. `/list`)
	LogURIPath bool
	// LogRequestID instructs logger to extract request ID from request `X-Request-ID` header or response if request did not have value.
	LogRequestID bool
	// LogReferer instructs logger to extract request referer values.
	LogReferer bool
	// LogUserAgent instructs logger to extract request user agent values.
	LogUserAgent bool
	// LogStatus instructs logger to extract response status code.
	LogStatus bool
	// LogContentLength instructs logger to extract content length header value. Note: this value could be different from
	// actual request body size as it could be spoofed etc.
	LogContentLength bool
	// LogResponseSize instructs logger to extract response content length value. Note: when used with Gzip middleware
	// this value may not be always correct.
	LogResponseSize bool
	// LogHeaders instructs logger to extract given list of headers from request. Note: request can contain more than
	// one header with same value so slice of values is been logger for each given header.
	//
	// Note: header values are converted to canonical form with http.CanonicalHeaderKey as this how request parser converts header
	// names to. For example, the canonical key for "accept-encoding" is "Accept-Encoding".
	LogHeaders []string
	// LogQueryParams instructs logger to extract given list of query parameters from request URI. Note: request can
	// contain more than one query parameter with same name so slice of values is been logger for each given query param name.
	LogQueryParams []string
	// LogFormValues instructs logger to extract given list of form values from request body+URI. Note: request can
	// contain more than one form value with same name so slice of values is been logger for each given form value name.
	LogFormValues []string
}

// RequestLoggerValues contains extracted values from logger.
type RequestLoggerValues struct {
	// StartTime is time recorded before next middleware/handler is executed.
	StartTime time.Time
	// Latency is duration it took to execute rest of the handler chain (next(c) call).
	Latency time.Duration
	// Protocol is request protocol (i.e. `HTTP/1.1` or `HTTP/2`)
	Protocol string
	// RemoteIP is request remote IP. See `echo.Context.RealIP()` for implementation details.
	RemoteIP string
	// Host is request host value (i.e. `example.com`)
	Host string
	// Method is request method value (i.e. `GET` etc)
	Method string
	// URI is request URI (i.e. `/list?lang=en&page=1`)
	URI string
	// URIPath is request URI path part (i.e. `/list`)
	URIPath string
	// RequestID is request ID from request `X-Request-ID` header or response if request did not have value.
	RequestID string
	// Referer is request referer values.
	Referer string
	// UserAgent is request user agent values.
	UserAgent string
	// Status is response status code. Then handler returns an echo.HTTPError then code from there.
	Status int
	// ContentLength is content length header value. Note: this value could be different from actual request body size
	// as it could be spoofed etc.
	ContentLength string
	// ResponseSize is response content length value. Note: when used with Gzip middleware this value may not be always correct.
	ResponseSize int64
	// Headers are list of headers from request. Note: request can contain more than one header with same value so slice
	// of values is been logger for each given header.
	// Note: header values are converted to canonical form with http.CanonicalHeaderKey as this how request parser converts header
	// names to. For example, the canonical key for "accept-encoding" is "Accept-Encoding".
	Headers map[string][]string
	// QueryParams are list of query parameters from request URI. Note: request can contain more than one query parameter
	// with same name so slice of values is been logger for each given query param name.
	QueryParams map[string][]string
	// FormValues are list of form values from request body+URI. Note: request can contain more than one form value with
	// same name so slice of values is been logger for each given form value name.
	FormValues map[string][]string
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

			// Execute the next handler
			m := httpsnoop.CaptureMetrics(next, w, r)

			// Calculate latency
			latency := time.Since(start)

			// Extract request values based on configuration
			values := &RequestLoggerValues{
				StartTime: start,
				Latency:   latency,
			}

			// Extract protocol if enabled
			if l.LogProtocol {
				values.Protocol = r.Proto
			}

			// Extract remote IP if enabled
			if l.LogRemoteIP {
				values.RemoteIP = r.RemoteAddr
			}

			// Extract host if enabled
			if l.LogHost {
				values.Host = r.Host
			}

			// Extract method if enabled
			if l.LogMethod {
				values.Method = r.Method
			}

			// Extract URI if enabled
			if l.LogURI {
				values.URI = r.RequestURI
			}

			// Extract URI path if enabled
			if l.LogURIPath {
				values.URIPath = r.URL.Path
			}

			// Extract request ID if enabled
			if l.LogRequestID {
				values.RequestID = r.Header.Get("X-Request-ID")
			}

			// Extract referer if enabled
			if l.LogReferer {
				values.Referer = r.Header.Get("Referer")
			}

			// Extract user agent if enabled
			if l.LogUserAgent {
				values.UserAgent = r.Header.Get("User-Agent")
			}

			// Extract status if enabled
			if l.LogStatus {
				values.Status = m.Code
			}

			// Extract content length if enabled
			if l.LogContentLength {
				values.ContentLength = r.Header.Get("Content-Length")
			}

			// Extract response size if enabled
			if l.LogResponseSize {
				values.ResponseSize = m.Written
			}

			// Extract headers if enabled
			if len(l.LogHeaders) > 0 {
				values.Headers = make(map[string][]string)
				for _, headerName := range l.LogHeaders {
					canonicalName := http.CanonicalHeaderKey(headerName)
					if headerValues, exists := r.Header[canonicalName]; exists {
						values.Headers[canonicalName] = headerValues
					}
				}
			}

			// Extract query parameters if enabled
			if len(l.LogQueryParams) > 0 {
				values.QueryParams = make(map[string][]string)
				for _, paramName := range l.LogQueryParams {
					if paramValues, exists := r.URL.Query()[paramName]; exists {
						values.QueryParams[paramName] = paramValues
					}
				}
			}

			// Extract form values if enabled
			if len(l.LogFormValues) > 0 {
				values.FormValues = make(map[string][]string)
				// Parse form if not already parsed
				if err := r.ParseForm(); err == nil {
					for _, formName := range l.LogFormValues {
						if formValues, exists := r.Form[formName]; exists {
							values.FormValues[formName] = formValues
						}
					}
				}
			}

			// Call the custom logging function if provided
			if l.LogValuesFunc != nil {
				l.LogValuesFunc(r, values)
			}
		})
	}
}

func New(opts ...Option) *Logger {
	o := option{
		Config: Logger{
			LogValuesFunc: func(r *http.Request, v *RequestLoggerValues) {
				slog.Debug("request",
					slog.String("user", r.Header.Get("X-User")),
					slog.String("route", r.Pattern),
					slog.String("request_id", v.RequestID),
					slog.String("remote_ip", v.RemoteIP),
					slog.String("host", v.Host),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.String("user_agent", v.UserAgent),
					slog.Int("status", v.Status),
					slog.Int64("latency", v.Latency.Nanoseconds()),
					slog.String("latency_human", v.Latency.String()),
					slog.String("bytes_in", v.ContentLength),
					slog.Int64("bytes_out", v.ResponseSize),
				)
			},
			LogLatency:       true,
			LogRemoteIP:      true,
			LogHost:          true,
			LogMethod:        true,
			LogURI:           true,
			LogRequestID:     true,
			LogReferer:       true,
			LogUserAgent:     true,
			LogStatus:        true,
			LogContentLength: true,
			LogResponseSize:  true,
		},
	}

	for _, opt := range opts {
		opt(&o)
	}

	return &o.Config
}

func Middleware(opts ...Option) func(next http.Handler) http.Handler {
	return New(opts...).Middleware()
}

// //////////////////////////////////////////////////////

type option struct {
	Config Logger
}

type Option func(*option)

func WithConfig(cfg Logger) Option {
	return func(o *option) {
		o.Config = cfg
	}
}
