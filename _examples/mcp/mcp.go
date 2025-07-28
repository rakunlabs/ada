package mcp

import (
	"context"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/ada/middlewares/mcp"
)

func Run(ctx context.Context) error {
	server, err := ada.NewWithFunc(ctx, func(ctx context.Context, mux *ada.Mux) error {
		mcpHandler := mcp.New()
		mux.Handle("/", mcpHandler)

		return nil
	})
	if err != nil {
		return err
	}

	return server.Start(ctx, ":8080")
}
