# MCP (Model Context Protocol)

An HTTP handler that implements the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) specification version `2025-11-25`. It provides a JSON-RPC 2.0 based server for exposing tools, resources, prompts, and completions to AI clients.

```go
"github.com/rakunlabs/ada/handler/mcp"
```

## Quick Start

```go
mcpManager := mcp.New()

// Configure server info
mcpManager.ServerName = "my-server"
mcpManager.ServerVersion = "1.0.0"
mcpManager.Instructions = "You are a helpful assistant."

// Mount the handler
mux.Handle("/*", mcpManager)
```

The handler implements `http.Handler` and accepts JSON-RPC 2.0 POST requests. It also handles OPTIONS preflight requests for CORS support.

## Tools

Tools are functions that AI clients can invoke. Each tool has a name, description, and a JSON Schema defining its input parameters.

```go
mcpManager.AddTool(mcp.Tool{
    Name:        "greet",
    Title:       "Greeter",
    Description: "Greets a person by name",
    InputSchema: map[string]any{
        "type": "object",
        "properties": map[string]any{
            "name": map[string]any{
                "type":        "string",
                "description": "Name of the person to greet",
            },
        },
        "required": []string{"name"},
    },
}, func(args map[string]any) (mcp.ToolCallResult, error) {
    name, _ := args["name"].(string)
    return mcp.NewToolCallResult("Hello, " + name + "!"), nil
})
```

### Tool Results

Use the helper constructors for creating results:

```go
// Successful text result
mcp.NewToolCallResult("Operation completed")

// Error result (isError: true)
mcp.NewToolCallErrorResult("Something went wrong")

// Custom result with multiple content items
mcp.ToolCallResult{
    Content: []any{
        mcp.NewTextContent("Here is the data:"),
        mcp.NewImageContent(base64Data, "image/png"),
    },
}
```

When a handler returns an `error`, it is automatically wrapped as a `ToolCallResult` with `isError: true`. This preserves the JSON-RPC response (no protocol-level error) and signals to the AI client that the tool execution failed.

## Resources

Resources expose data that AI clients can read by URI.

```go
mcpManager.AddResource(mcp.Resource{
    URI:         "config://app-settings",
    Name:        "Application Settings",
    Description: "Current application configuration",
    MimeType:    "application/json",
}, func(uri string) (mcp.ResourceContent, error) {
    return mcp.ResourceContent{
        URI:      uri,
        MimeType: "application/json",
        Text:     `{"debug": false, "version": "1.0.0"}`,
    }, nil
})
```

### Resource Templates

Resource templates define URI patterns for dynamic resources.

```go
mcpManager.AddResourceTemplate(mcp.ResourceTemplate{
    URITemplate: "users://{userId}/profile",
    Name:        "User Profile",
    Description: "Profile data for a specific user",
    MimeType:    "application/json",
})
```

## Prompts

Prompts are reusable message templates that AI clients can retrieve.

```go
mcpManager.AddPrompt(mcp.Prompt{
    Name:        "summarize",
    Title:       "Summarize Text",
    Description: "Summarizes given text",
    Arguments: []mcp.PromptArg{
        {
            Name:        "text",
            Description: "Text to summarize",
            Required:    true,
        },
        {
            Name:        "style",
            Description: "Summary style (brief, detailed)",
            Required:    false,
        },
    },
}, func(args map[string]string) (mcp.GetPromptResult, error) {
    text := args["text"]
    style := args["style"]
    if style == "" {
        style = "brief"
    }

    return mcp.GetPromptResult{
        Description: "Summarization prompt",
        Messages: []mcp.PromptMessage{
            {
                Role: "user",
                Content: mcp.PromptContent{
                    Type: "text",
                    Text: fmt.Sprintf("Summarize the following text in a %s style:\n\n%s", style, text),
                },
            },
        },
    }, nil
})
```

## Completions

Completion handlers provide auto-complete suggestions for prompt arguments or resource URIs.

```go
// Register a completion handler for a prompt argument
mcpManager.AddCompletionHandler("prompt:summarize", func(req mcp.CompleteRequest) (mcp.CompletionValues, error) {
    if req.Argument.Name == "style" {
        return mcp.CompletionValues{
            Values: []string{"brief", "detailed", "bullet-points"},
        }, nil
    }
    return mcp.CompletionValues{Values: []string{}}, nil
})

// Register a completion handler for a resource URI
mcpManager.AddCompletionHandler("resource:users://{userId}/profile", func(req mcp.CompleteRequest) (mcp.CompletionValues, error) {
    return mcp.CompletionValues{
        Values:  []string{"user-1", "user-2", "user-3"},
        HasMore: true,
        Total:   100,
    }, nil
})
```

The reference key format is `prompt:<name>` for prompt completions and `resource:<uri>` for resource completions.

## Content Types

The package provides typed constructors for all MCP content types:

| Constructor | Type Field | Description |
|---|---|---|
| `NewTextContent(text)` | `"text"` | Plain text content |
| `NewImageContent(data, mimeType)` | `"image"` | Base64-encoded image |
| `NewAudioContent(data, mimeType)` | `"audio"` | Base64-encoded audio |
| `NewResourceLinkContent(uri)` | `"resource_link"` | Link to a resource |
| `NewEmbeddedResourceContent(resource)` | `"resource"` | Embedded resource |

## Supported Methods

### Requests (require response)

| Method | Description |
|---|---|
| `initialize` | Client-server handshake |
| `ping` | Health check (returns `{}`) |
| `tools/list` | List registered tools |
| `tools/call` | Execute a tool |
| `resources/list` | List registered resources |
| `resources/read` | Read a resource by URI |
| `resources/templates/list` | List resource templates |
| `resources/subscribe` | Subscribe to resource updates |
| `resources/unsubscribe` | Unsubscribe from resource updates |
| `prompts/list` | List registered prompts |
| `prompts/get` | Get a prompt by name with arguments |
| `completion/complete` | Get completion suggestions |
| `logging/setLevel` | Set server log level |

### Notifications (no response)

| Notification | Description |
|---|---|
| `notifications/initialized` | Client finished initialization |
| `notifications/cancelled` | Client cancelled a request |
| `notifications/tools/list_changed` | Tools list changed |
| `notifications/resources/list_changed` | Resources list changed |
| `notifications/resources/updated` | A resource was updated |
| `notifications/prompts/list_changed` | Prompts list changed |
| `notifications/message` | Log message |
| `notifications/tasks/status` | Task status update |

## Full Example

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"

    "github.com/rakunlabs/ada"
    "github.com/rakunlabs/ada/handler/mcp"
    "github.com/shopspring/decimal"

    mlog "github.com/rakunlabs/ada/middleware/log"
)

func main() {
    ctx := context.Background()

    server, err := ada.NewWithFunc(ctx, func(ctx context.Context, mux *ada.Mux) error {
        mcpManager := mcp.New()
        mcpManager.ServerName = "calculator-server"
        mcpManager.ServerVersion = "1.0.0"
        mcpManager.Instructions = "You are a calculator assistant."

        mcpManager.AddTool(mcp.Tool{
            Name:        "calculator",
            Title:       "Calculator",
            Description: "Perform basic arithmetic operations",
            InputSchema: map[string]any{
                "type": "object",
                "properties": map[string]any{
                    "operation": map[string]any{
                        "type":        "string",
                        "description": "Operation to perform",
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
        }, func(args map[string]any) (mcp.ToolCallResult, error) {
            operation, _ := args["operation"].(string)
            a, _ := args["a"].(json.Number)
            b, _ := args["b"].(json.Number)

            var result string
            switch operation {
            case "add":
                result = decimal.RequireFromString(a.String()).
                    Add(decimal.RequireFromString(b.String())).String()
            case "subtract":
                result = decimal.RequireFromString(a.String()).
                    Sub(decimal.RequireFromString(b.String())).String()
            case "multiply":
                result = decimal.RequireFromString(a.String()).
                    Mul(decimal.RequireFromString(b.String())).String()
            case "divide":
                bDec := decimal.RequireFromString(b.String())
                if bDec.Equal(decimal.Zero) {
                    return mcp.ToolCallResult{}, fmt.Errorf("division by zero")
                }
                result = decimal.RequireFromString(a.String()).Div(bDec).String()
            default:
                return mcp.ToolCallResult{}, fmt.Errorf("unknown operation: %s", operation)
            }

            return mcp.NewToolCallResult(fmt.Sprintf("Result: %s", result)), nil
        })

        mcpManager.AddResource(mcp.Resource{
            URI:         "data://server-info",
            Name:        "Server Information",
            Description: "Server metadata",
            MimeType:    "application/json",
        }, func(uri string) (mcp.ResourceContent, error) {
            return mcp.ResourceContent{
                URI:      uri,
                MimeType: "application/json",
                Text:     `{"server":"calculator-server","version":"1.0.0"}`,
            }, nil
        })

        mcpManager.AddPrompt(mcp.Prompt{
            Name:        "calculate",
            Description: "Perform arithmetic calculations",
            Arguments: []mcp.PromptArg{
                {Name: "operation", Description: "Operation to perform", Required: true},
                {Name: "a", Description: "First number", Required: true},
                {Name: "b", Description: "Second number", Required: true},
            },
        }, func(args map[string]string) (mcp.GetPromptResult, error) {
            return mcp.GetPromptResult{
                Description: "Calculation prompt",
                Messages: []mcp.PromptMessage{
                    {
                        Role: "user",
                        Content: mcp.PromptContent{
                            Type: "text",
                            Text: fmt.Sprintf("Calculate %s %s %s",
                                args["a"], args["operation"], args["b"]),
                        },
                    },
                },
            }, nil
        })

        mux.Use(mlog.Middleware())
        mux.Handle("/*", mcpManager)

        return nil
    })
    if err != nil {
        panic(err)
    }

    server.StartWithContext(ctx, ":8080")
}
```

### Testing with curl

```sh
# Initialize
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}'

# List tools
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# Call a tool
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"calculator","arguments":{"operation":"add","a":10,"b":5}}}'
```
