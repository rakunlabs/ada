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
	mserver "github.com/rakunlabs/ada/middleware/server"
	mtelemetry "github.com/rakunlabs/ada/middleware/telemetry"
)

func Run(ctx context.Context) error {
	server, err := ada.NewWithFunc(ctx, func(_ context.Context, mux *ada.Mux) error {
		mux.Use(
			mrecover.Middleware(),
			mserver.Middleware("MyServer"),
			mrequestid.Middleware(),
			mlog.Middleware(),
		)

		// grpc handler
		gRPChelloHandler := NewHelloHandler()
		mux.HandleWildcard(gRPChelloHandler.Handler())

		// add gRPC health check
		healthChecker := grpchealth.NewStaticChecker(gRPChelloHandler.ServiceName())
		mux.HandleWildcard(grpchealth.NewHandler(healthChecker))

		// add gRPC reflection
		reflector := grpcreflect.NewStaticReflector(gRPChelloHandler.ServiceName())
		mux.HandleWildcard(grpcreflect.NewHandlerV1(reflector))
		mux.HandleWildcard(grpcreflect.NewHandlerV1Alpha(reflector))

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
