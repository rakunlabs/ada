package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type Tools struct {
	list []Tool

	m sync.RWMutex
}

func (t *Tools) Add(tool Tool) {
	t.m.Lock()
	defer t.m.Unlock()

	t.list = append(t.list, tool)
}

func (s *MCP) handleToolsList(id any) JSONRPCResponse {
	tools := []Tool{
		{
			Name:        "echo",
			Description: "Echo back the input text",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]any{
						"type":        "string",
						"description": "Text to echo back",
					},
				},
				"required": []string{"text"},
			},
		},
		{
			Name:        "uppercase",
			Description: "Convert text to uppercase",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]any{
						"type":        "string",
						"description": "Text to convert to uppercase",
					},
				},
				"required": []string{"text"},
			},
		},
		{
			Name:        "word_count",
			Description: "Count words in the given text",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]any{
						"type":        "string",
						"description": "Text to count words in",
					},
				},
				"required": []string{"text"},
			},
		},
	}

	result := map[string]any{
		"tools": tools,
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handleToolsCall(id any, params json.RawMessage) JSONRPCResponse {
	var callParams struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}

	if err := json.Unmarshal(params, &callParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	var result map[string]any

	switch callParams.Name {
	case "echo":
		if text, ok := callParams.Arguments["text"].(string); ok {
			result = map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": fmt.Sprintf("Echo: %s", text),
					},
				},
			}
		} else {
			return s.createErrorResponse(id, -32602, "Missing or invalid 'text' parameter")
		}
	case "uppercase":
		if text, ok := callParams.Arguments["text"].(string); ok {
			result = map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": strings.ToUpper(text),
					},
				},
			}
		} else {
			return s.createErrorResponse(id, -32602, "Missing or invalid 'text' parameter")
		}
	case "word_count":
		if text, ok := callParams.Arguments["text"].(string); ok {
			words := strings.Fields(text)
			count := len(words)
			result = map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": fmt.Sprintf("Word count: %d", count),
					},
				},
			}
		} else {
			return s.createErrorResponse(id, -32602, "Missing or invalid 'text' parameter")
		}
	default:
		return s.createErrorResponse(id, -32601, "Unknown tool: "+callParams.Name)
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}
