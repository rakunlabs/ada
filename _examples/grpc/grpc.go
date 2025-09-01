package grpc

import (
	"context"
	"io"
	"net/http"

	"github.com/rakunlabs/ada"

	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"

	mcors "github.com/rakunlabs/ada/middleware/cors"
	mlog "github.com/rakunlabs/ada/middleware/log"
	mrecover "github.com/rakunlabs/ada/middleware/recover"
	mrequestid "github.com/rakunlabs/ada/middleware/requestid"
	mtelemetry "github.com/rakunlabs/ada/middleware/telemetry"
)

func Run(ctx context.Context) error {
	server, err := ada.NewWithFunc(ctx, func(_ context.Context, mux *ada.Mux) error {
		mux.Use(
			mrecover.Middleware(),
			mrequestid.Middleware(),
			mlog.Middleware(),
		)

		// grpc handler
		gRPChelloHandler := NewHelloHandler()
		mux.HandleAll(gRPChelloHandler.Handler())

		// add gRPC health check
		healthChecker := grpchealth.NewStaticChecker(gRPChelloHandler.ServiceName())
		mux.HandleAll(grpchealth.NewHandler(healthChecker))

		// add gRPC reflection
		reflector := grpcreflect.NewStaticReflector(gRPChelloHandler.ServiceName())
		mux.HandleAll(grpcreflect.NewHandlerV1(reflector))
		mux.HandleAll(grpcreflect.NewHandlerV1Alpha(reflector))

		// add http handler
		mux.Use(
			mcors.Middleware(),
			mtelemetry.Middleware(),
		)
		mux.POST("/hello", mux.Wrap(SayHello))

		return nil
	})
	if err != nil {
		return err
	}

	return server.StartWithContext(ctx, ":8080")
}

func SayHello(c *ada.Context) error {
	name, err := io.ReadAll(io.LimitReader(c.Request.Body, 100))
	if err != nil {
		return c.SetStatus(http.StatusInternalServerError).SendJSON(map[string]string{"error": "Failed to read request body"})
	}

	return c.SetStatus(http.StatusOK).SendJSON(map[string]string{"message": "Hello, " + string(name)})
}
