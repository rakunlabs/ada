package log

import (
	"log/slog"
	"net/http"
	"time"
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
	// LogStatus instructs logger to extract response status code. If handler chain returns an echo.HTTPError,
	// the status code is extracted from the echo.HTTPError returned
	LogStatus bool
	// LogError instructs logger to extract error returned from executed handler chain.
	LogError bool
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
	// Error is error returned from executed handler chain.
	Error error
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
			next.ServeHTTP(w, r)

			// TODO: implement logging logic here
		})
	}
}

func New(opts ...Option) *Logger {
	o := option{
		Config: Logger{
			LogValuesFunc: func(r *http.Request, v *RequestLoggerValues) {
				slog.Debug("request",
					slog.String("user", r.Header.Get("X-User")),
					slog.String("request_id", v.RequestID),
					slog.String("remote_ip", v.RemoteIP),
					slog.String("host", v.Host),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.String("user_agent", v.UserAgent),
					slog.Int("status", v.Status),
					slog.String("error", v.Error.Error()),
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
			LogError:         true,
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
