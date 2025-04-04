package serverecho

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rakunlabs/logz/logecho"
	"github.com/rakunlabs/tell/metric/metricecho"
	"github.com/rs/zerolog/log"
	"github.com/ziflex/lecho/v3"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
)

type Config struct {
	ServiceName string
}

func New(fn func(ctx context.Context, mux *http.ServeMux, e *echo.Echo) error, cfg Config) func(ctx context.Context, mux *http.ServeMux) error {
	return func(ctx context.Context, mux *http.ServeMux) error {
		// echo server
		e := echo.New()
		e.HideBanner = true

		e.Validator = NewValidator()

		e.Logger = lecho.From(log.Logger)

		e.Use(
			middleware.Recover(),
			middleware.CORS(),
			middleware.RequestID(),
			middleware.RequestLoggerWithConfig(logecho.RequestLoggerConfig()),
			logecho.ZerologLogger(),
			metricecho.HTTPMetrics(),
			otelecho.Middleware(cfg.ServiceName),
			MiddlewareUserInfo,
		)

		e.HTTPErrorHandler = HTTPErrorHandler

		return fn(ctx, mux, e)
	}
}
