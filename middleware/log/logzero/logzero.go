// Package logzero switches middleware/log defaults to zerolog when imported.
package logzero

import (
	"net/http"

	mlog "github.com/rakunlabs/ada/middleware/log"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func init() {
	mlog.SetDefaultLogger(func() mlog.Logger {
		return mlog.Logger{
			PreFunc: func(r *http.Request) *http.Request {
				logger := log.With()
				if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
					logger = logger.Str("request_id", requestID)
				}
				if user := r.Header.Get("X-User"); user != "" {
					logger = logger.Str("user", user)
				}
				if userAgent := mlog.UserAgent(r); userAgent != "" {
					logger = logger.Str("user_agent", userAgent)
				}

				ctxLogger := logger.Logger()
				return r.WithContext(ctxLogger.WithContext(r.Context()))
			},
			PostFunc: func(r *http.Request, v *mlog.Response) {
				zerolog.Ctx(r.Context()).Debug().
					Str("user", r.Header.Get("X-User")).
					Str("route", r.Pattern).
					Str("request_id", r.Header.Get("X-Request-ID")).
					Str("remote_ip", mlog.RealIP(r)).
					Str("host", r.Host).
					Str("method", r.Method).
					Str("uri", r.RequestURI).
					Str("user_agent", mlog.UserAgent(r)).
					Int("status", v.Status).
					Int64("latency", v.Latency.Nanoseconds()).
					Str("latency_human", v.Latency.String()).
					Str("bytes_in", r.Header.Get("Content-Length")).
					Int64("bytes_out", v.ResponseSize).
					Msg("request")
			},
		}
	})
}
