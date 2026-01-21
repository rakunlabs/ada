package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/ada/handler/mcp"
	"github.com/shopspring/decimal"

	mlog "github.com/rakunlabs/ada/middleware/log"
)

func Run(ctx context.Context) error {
	server, err := ada.NewWithFunc(ctx, func(ctx context.Context, mux *ada.Mux) error {
		// Create a new MCP server
		server := mcp.New()

		// Add a custom tool
		server.AddTool(mcp.Tool{
			Name:        "calculator",
			Description: "Perform basic arithmetic operations",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"operation": map[string]any{
						"type":        "string",
						"description": "Operation to perform (add, subtract, multiply, divide)",
						"enum":        []string{"add", "subtract", "multiply", "divide"},
					},
					"a": map[string]any{
						"type":        "number",
						"description": "First number",
					},
					"b": map[string]any{
						"type":        "number",
						"description": "Second number",
					},
				},
				"required": []string{"operation", "a", "b"},
			},
		}, func(args map[string]any) (any, error) {
			operation, ok := args["operation"].(string)
			if !ok {
				return nil, fmt.Errorf("invalid operation")
			}

			a, ok := args["a"].(json.Number)
			if !ok {
				return nil, fmt.Errorf("invalid first number")
			}

			b, ok := args["b"].(json.Number)
			if !ok {
				return nil, fmt.Errorf("invalid second number")
			}

			var result string
			switch operation {
			case "add":
				result = decimal.RequireFromString(a.String()).Add(decimal.RequireFromString(b.String())).String()
			case "subtract":
				result = decimal.RequireFromString(a.String()).Sub(decimal.RequireFromString(b.String())).String()
			case "multiply":
				result = decimal.RequireFromString(a.String()).Mul(decimal.RequireFromString(b.String())).String()
			case "divide":
				if decimal.RequireFromString(b.String()).Equal(decimal.Zero) {
					return nil, fmt.Errorf("division by zero")
				}
				result = decimal.RequireFromString(a.String()).Div(decimal.RequireFromString(b.String())).String()
			default:
				return nil, fmt.Errorf("unknown operation: %s", operation)
			}

			return map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": fmt.Sprintf("Result: %s", result),
					},
				},
			}, nil
		})

		// Add a custom resource
		server.AddResource(mcp.Resource{
			URI:         "data://custom-info",
			Name:        "Custom Information",
			Description: "Custom server information",
			MimeType:    "application/json",
		}, func(uri string) (any, error) {
			return map[string]any{
				"server":    "custom-mcp-server",
				"version":   "1.0.0",
				"features":  []string{"calculator"},
				"timestamp": "2025-01-13T10:00:00Z",
			}, nil
		})

		// Add a custom prompt
		server.AddPrompt(mcp.Prompt{
			Name:        "calculate",
			Title:       "Calculator",
			Description: "Perform arithmetic calculations",
			Arguments: []mcp.PromptArg{
				{
					Name:        "operation",
					Description: "Operation to perform (add, subtract, multiply, divide)",
					Required:    true,
				},
				{
					Name:        "a",
					Description: "First number",
					Required:    true,
				},
				{
					Name:        "b",
					Description: "Second number",
					Required:    true,
				},
			},
		}, func(args map[string]string) (mcp.GetPromptResult, error) {
			operation := args["operation"]
			a := args["a"]
			b := args["b"]

			return mcp.GetPromptResult{
				Description: "Calculation prompt",
				Messages: []mcp.PromptMessage{
					{
						Role: "user",
						Content: mcp.PromptContent{
							Type: "text",
							Text: fmt.Sprintf("Calculate %s %s %s", a, operation, b),
						},
					},
				},
			}, nil
		})

		mux.Use(mlog.Middleware())
		mux.Handle("/*", server)

		return nil
	})
	if err != nil {
		return err
	}

	return server.StartWithContext(ctx, ":8080")
}
