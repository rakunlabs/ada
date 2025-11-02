package main

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/rakunlabs/into"
	"github.com/rakunlabs/logi"
	"github.com/rakunlabs/tell"

	"github.com/rakunlabs/ada/_examples/bind"
	"github.com/rakunlabs/ada/_examples/folder"
	"github.com/rakunlabs/ada/_examples/grpc"
	"github.com/rakunlabs/ada/_examples/hello"
	"github.com/rakunlabs/ada/_examples/mcp"
	"github.com/rakunlabs/ada/_examples/swagger"
)

func main() {
	into.Init(
		run,
		into.WithMsgf("ADA Examples"),
		into.WithLogger(logi.InitializeLog(logi.WithLevel("DEBUG"))),
	)
}

var Examples = map[string]func(ctx context.Context) error{
	"grpc":    grpc.Run,
	"mcp":     mcp.Run,
	"hello":   hello.Run,
	"bind":    bind.Run,
	"folder":  folder.Run,
	"swagger": swagger.Run,
}

func run(ctx context.Context) error {
	collector, err := tell.New(ctx, tell.Config{})
	if err != nil {
		return fmt.Errorf("failed to init telemetry; %w", err)
	}
	defer collector.Shutdown()

	example := strings.ToLower(os.Getenv("EXAMPLE"))

	if v := Examples[example]; v != nil {
		slog.Info("running example", "example", example)
		return v(ctx)
	}

	return fmt.Errorf("unknown EXAMPLE env: [%s] on [ %s ]", example, strings.Join(slices.Collect(maps.Keys(Examples)), ", "))
}
