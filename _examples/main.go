package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/rakunlabs/into"
	"github.com/rakunlabs/logi"

	"github.com/rakunlabs/ada/examples/hello"
	"github.com/rakunlabs/ada/examples/mcp"
)

func main() {
	into.Init(
		run,
		into.WithMsgf("ADA Examples"),
		into.WithLogger(logi.InitializeLog(logi.WithLevel("DEBUG"))),
	)
}

var Examples = map[string]func(ctx context.Context) error{
	"mcp":   mcp.Run,
	"hello": hello.Run,
}

func listExamples() string {
	var sb strings.Builder
	sb.WriteString("[")
	for k := range Examples {
		sb.WriteString(fmt.Sprintf(" %s", k))
	}
	sb.WriteString(" ]")

	return sb.String()
}

func run(ctx context.Context) error {
	example := strings.ToLower(os.Getenv("EXAMPLE"))

	if v := Examples[example]; v != nil {
		slog.Info("running example", "example", example)
		return v(ctx)
	}

	return fmt.Errorf("unknown EXAMPLE env: [%s] on %s", example, listExamples())
}
