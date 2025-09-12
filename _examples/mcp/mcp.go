package mcp

import (
	"context"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/ada/handler/mcp"

	mlog "github.com/rakunlabs/ada/middleware/log"
)

func Run(ctx context.Context) error {
	server, err := ada.NewWithFunc(ctx, func(ctx context.Context, mux *ada.Mux) error {
		mcpHandler := mcp.New()

		mux.Use(mlog.Middleware())
		mux.Handle("/*", mcpHandler)

		return nil
	})
	if err != nil {
		return err
	}

	return server.StartWithContext(ctx, ":8080")
}
