package mcp

import (
	"context"
	"fmt"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/ada/handler/mcp"

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

			a, ok := args["a"].(float64)
			if !ok {
				return nil, fmt.Errorf("invalid first number")
			}

			b, ok := args["b"].(float64)
			if !ok {
				return nil, fmt.Errorf("invalid second number")
			}

			var result float64
			switch operation {
			case "add":
				result = a + b
			case "subtract":
				result = a - b
			case "multiply":
				result = a * b
			case "divide":
				if b == 0 {
					return nil, fmt.Errorf("division by zero")
				}
				result = a / b
			default:
				return nil, fmt.Errorf("unknown operation: %s", operation)
			}

			return map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": fmt.Sprintf("Result: %.2f", result),
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
				"features":  []string{"calculator", "custom-data"},
				"timestamp": "2025-01-13T10:00:00Z",
			}, nil
		})

		// Add a custom prompt
		server.AddPrompt(mcp.Prompt{
			Name:        "write_email",
			Title:       "Email Writer",
			Description: "Generate professional emails",
			Arguments: []mcp.PromptArg{
				{
					Name:        "recipient",
					Description: "Email recipient",
					Required:    true,
				},
				{
					Name:        "subject",
					Description: "Email subject",
					Required:    true,
				},
				{
					Name:        "tone",
					Description: "Email tone (formal, casual, friendly)",
					Required:    false,
				},
			},
		}, func(args map[string]string) (mcp.GetPromptResult, error) {
			recipient := args["recipient"]
			subject := args["subject"]
			tone := args["tone"]
			if tone == "" {
				tone = "formal"
			}

			return mcp.GetPromptResult{
				Description: "Email writing prompt",
				Messages: []mcp.PromptMessage{
					{
						Role: "user",
						Content: mcp.PromptContent{
							Type: "text",
							Text: fmt.Sprintf("Write a %s email to %s with the subject '%s'. Make it professional and appropriate for the context.", tone, recipient, subject),
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
