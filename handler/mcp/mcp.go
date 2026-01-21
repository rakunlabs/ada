package mcp

import (
	"encoding/json"
)

type MCP struct {
	Tools     Tools
	Resources Resources
	Prompts   Prompts
}

// ToolHandler represents a function that handles tool calls
type ToolHandler func(args map[string]any) (any, error)

// ResourceHandler represents a function that provides resource content
type ResourceHandler func(uri string) (any, error)

// PromptHandler represents a function that generates prompt content
type PromptHandler func(args map[string]string) (GetPromptResult, error)

func New() *MCP {
	mcp := &MCP{
		Tools: Tools{
			handlers: make(map[string]ToolHandler),
		},
		Resources: Resources{
			handlers: make(map[string]ResourceHandler),
		},
		Prompts: Prompts{
			handlers: make(map[string]PromptHandler),
		},
	}

	return mcp
}

func (s *MCP) handleInitialize(id any, params json.RawMessage) JSONRPCResponse {
	var initParams InitializeParams
	if err := decodeJSON(params, &initParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	result := InitializeResult{
		ProtocolVersion: "2025-06-18",
		Capabilities: Capabilities{
			Tools: &ToolsCapability{
				ListChanged: false,
			},
			Resources: &ResourcesCapability{
				Subscribe:   true,
				ListChanged: false,
			},
			Prompts: &PromptsCapability{
				ListChanged: false,
			},
			Logging:     &LoggingCapability{},
			Completions: &CompletionsCapability{},
		},
		ServerInfo: ServerInfo{
			Name:    "example-go-http-server",
			Version: "1.0.0",
		},
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handleInitialized() {
	// Client has finished initialization, server can now send requests
	// This is a notification, so no response is sent
	// In a real implementation, you might want to store the initialized state
	// or perform some setup operations here
}

func (s *MCP) handlePromptsList(id any) JSONRPCResponse {
	prompts := s.Prompts.List()

	result := map[string]any{
		"prompts": prompts,
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handlePromptsGet(id any, params json.RawMessage) JSONRPCResponse {
	var getParams struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments,omitempty"`
	}

	if err := decodeJSON(params, &getParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	// Get the handler for this prompt
	handler := s.Prompts.GetHandler(getParams.Name)
	if handler == nil {
		return s.createErrorResponse(id, -32602, "Unknown prompt: "+getParams.Name)
	}

	// Call the handler
	result, err := handler(getParams.Arguments)
	if err != nil {
		return s.createErrorResponse(id, -32603, "Prompt generation error: "+err.Error())
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handleResourcesTemplatesList(id any) JSONRPCResponse {
	templates := []ResourceTemplate{
		{
			URITemplate: "file:///{path}",
			Name:        "Project Files",
			Title:       "Project Files",
			Description: "Access files in the project directory",
			MimeType:    "application/octet-stream",
		},
		{
			URITemplate: "config://{section}",
			Name:        "Configuration",
			Title:       "Configuration Sections",
			Description: "Access configuration sections",
			MimeType:    "application/json",
		},
	}

	result := map[string]any{
		"resourceTemplates": templates,
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handleResourcesSubscribe(id any, params json.RawMessage) JSONRPCResponse {
	var subscribeParams SubscribeRequest
	if err := decodeJSON(params, &subscribeParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	// In a real implementation, you would store the subscription
	// For now, just acknowledge the subscription
	result := map[string]any{}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handleResourcesUnsubscribe(id any, params json.RawMessage) JSONRPCResponse {
	var unsubscribeParams UnsubscribeRequest
	if err := decodeJSON(params, &unsubscribeParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	// In a real implementation, you would remove the subscription
	// For now, just acknowledge the unsubscription
	result := map[string]any{}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handleCompletionComplete(id any, params json.RawMessage) JSONRPCResponse {
	var completeParams CompleteRequest
	if err := decodeJSON(params, &completeParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	var values []string

	// Provide completion suggestions based on the reference type and argument
	switch completeParams.Ref.Type {
	case "ref/prompt":
		if completeParams.Ref.Name == "code_review" && completeParams.Argument.Name == "language" {
			values = []string{"python", "javascript", "go", "java", "typescript", "rust", "cpp", "c"}
		} else if completeParams.Ref.Name == "explain_concept" && completeParams.Argument.Name == "audience" {
			values = []string{"beginner", "intermediate", "expert"}
		}
	case "ref/resource":
		if completeParams.Argument.Name == "path" {
			values = []string{"src/main.go", "config/app.json", "README.md", "docs/api.md"}
		}
	}

	result := CompleteResult{
		Completion: CompletionValues{
			Values:  values,
			Total:   len(values),
			HasMore: false,
		},
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handleLoggingSetLevel(id any, params json.RawMessage) JSONRPCResponse {
	var levelParams SetLevelRequest
	if err := decodeJSON(params, &levelParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	// In a real implementation, you would set the logging level
	// For now, just acknowledge the request
	result := map[string]any{}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

// Default initialization methods
// func (s *MCP) addDefaultTools() {
// 	// Add the built-in tools
// 	s.Tools.Add(Tool{
// 		Name:        "echo",
// 		Description: "Echo back the input text",
// 		InputSchema: map[string]any{
// 			"type": "object",
// 			"properties": map[string]any{
// 				"text": map[string]any{
// 					"type":        "string",
// 					"description": "Text to echo back",
// 				},
// 			},
// 			"required": []string{"text"},
// 		},
// 	}, func(args map[string]any) (any, error) {
// 		if text, ok := args["text"].(string); ok {
// 			return map[string]any{
// 				"content": []map[string]any{
// 					{
// 						"type": "text",
// 						"text": fmt.Sprintf("Echo: %s", text),
// 					},
// 				},
// 			}, nil
// 		}
// 		return nil, fmt.Errorf("missing or invalid 'text' parameter")
// 	})

// 	s.Tools.Add(Tool{
// 		Name:        "uppercase",
// 		Description: "Convert text to uppercase",
// 		InputSchema: map[string]any{
// 			"type": "object",
// 			"properties": map[string]any{
// 				"text": map[string]any{
// 					"type":        "string",
// 					"description": "Text to convert to uppercase",
// 				},
// 			},
// 			"required": []string{"text"},
// 		},
// 	}, func(args map[string]any) (any, error) {
// 		if text, ok := args["text"].(string); ok {
// 			return map[string]any{
// 				"content": []map[string]any{
// 					{
// 						"type": "text",
// 						"text": strings.ToUpper(text),
// 					},
// 				},
// 			}, nil
// 		}
// 		return nil, fmt.Errorf("missing or invalid 'text' parameter")
// 	})

// 	s.Tools.Add(Tool{
// 		Name:        "word_count",
// 		Description: "Count words in the given text",
// 		InputSchema: map[string]any{
// 			"type": "object",
// 			"properties": map[string]any{
// 				"text": map[string]any{
// 					"type":        "string",
// 					"description": "Text to count words in",
// 				},
// 			},
// 			"required": []string{"text"},
// 		},
// 	}, func(args map[string]any) (any, error) {
// 		if text, ok := args["text"].(string); ok {
// 			words := strings.Fields(text)
// 			count := len(words)
// 			return map[string]any{
// 				"content": []map[string]any{
// 					{
// 						"type": "text",
// 						"text": fmt.Sprintf("Word count: %d", count),
// 					},
// 				},
// 			}, nil
// 		}
// 		return nil, fmt.Errorf("missing or invalid 'text' parameter")
// 	})
// }

// func (s *MCP) addDefaultResources() {
// 	// Add built-in resources
// 	s.Resources.Add(Resource{
// 		URI:         "config://server-info",
// 		Name:        "Server Information",
// 		Description: "Information about this MCP server",
// 		MimeType:    "application/json",
// 	}, func(uri string) (any, error) {
// 		return map[string]any{
// 			"name":    "example-go-http-server",
// 			"version": "1.0.0",
// 			"port":    8080,
// 			"capabilities": []string{
// 				"tools",
// 				"resources",
// 				"prompts",
// 			},
// 		}, nil
// 	})

// 	s.Resources.Add(Resource{
// 		URI:         "data://sample-text",
// 		Name:        "Sample Text",
// 		Description: "A sample text resource",
// 		MimeType:    "text/plain",
// 	}, func(uri string) (any, error) {
// 		return "This is a sample text resource served by the MCP HTTP server.\nIt can contain multiple lines and various content.", nil
// 	})
// }

// func (s *MCP) addDefaultPrompts() {
// 	// Add built-in prompts
// 	s.Prompts.Add(Prompt{
// 		Name:        "code_review",
// 		Title:       "Code Review Assistant",
// 		Description: "Asks the LLM to analyze code quality and suggest improvements",
// 		Arguments: []PromptArg{
// 			{
// 				Name:        "code",
// 				Description: "The code to review",
// 				Required:    true,
// 			},
// 			{
// 				Name:        "language",
// 				Description: "Programming language of the code",
// 				Required:    false,
// 			},
// 		},
// 	}, func(args map[string]string) (GetPromptResult, error) {
// 		code := args["code"]
// 		language := args["language"]
// 		if language == "" {
// 			language = "unknown"
// 		}

// 		return GetPromptResult{
// 			Description: "Code review prompt for " + language,
// 			Messages: []PromptMessage{
// 				{
// 					Role: "user",
// 					Content: PromptContent{
// 						Type: "text",
// 						Text: fmt.Sprintf("Please review the following %s code and provide feedback on:\n1. Code quality and best practices\n2. Potential bugs or issues\n3. Performance considerations\n4. Security concerns\n\nCode:\n```%s\n%s\n```", language, language, code),
// 					},
// 				},
// 			},
// 		}, nil
// 	})

// 	s.Prompts.Add(Prompt{
// 		Name:        "explain_concept",
// 		Title:       "Concept Explainer",
// 		Description: "Explains technical concepts in simple terms",
// 		Arguments: []PromptArg{
// 			{
// 				Name:        "concept",
// 				Description: "The concept to explain",
// 				Required:    true,
// 			},
// 			{
// 				Name:        "audience",
// 				Description: "Target audience (beginner, intermediate, expert)",
// 				Required:    false,
// 			},
// 		},
// 	}, func(args map[string]string) (GetPromptResult, error) {
// 		concept := args["concept"]
// 		audience := args["audience"]
// 		if audience == "" {
// 			audience = "intermediate"
// 		}

// 		return GetPromptResult{
// 			Description: "Concept explanation for " + audience + " audience",
// 			Messages: []PromptMessage{
// 				{
// 					Role: "user",
// 					Content: PromptContent{
// 						Type: "text",
// 						Text: fmt.Sprintf("Please explain the concept of '%s' to a %s audience. Use simple language, provide examples, and break down complex ideas into understandable parts.", concept, audience),
// 					},
// 				},
// 			},
// 		}, nil
// 	})
// }

// Public API methods for users to register their own tools, resources, and prompts

// AddTool allows users to register their own tools
func (s *MCP) AddTool(tool Tool, handler ToolHandler) {
	s.Tools.Add(tool, handler)
}

// AddResource allows users to register their own resources
func (s *MCP) AddResource(resource Resource, handler ResourceHandler) {
	s.Resources.Add(resource, handler)
}

// AddPrompt allows users to register their own prompts
func (s *MCP) AddPrompt(prompt Prompt, handler PromptHandler) {
	s.Prompts.Add(prompt, handler)
}

// Notification handlers
func (s *MCP) handleToolsListChanged() {
	// Handle tools list changed notification
	// In a real implementation, you might update caches or notify other components
}

func (s *MCP) handleResourcesListChanged() {
	// Handle resources list changed notification
	// In a real implementation, you might update caches or notify subscribers
}

func (s *MCP) handleResourceUpdated(params json.RawMessage) {
	var updateParams ResourceUpdatedNotification
	if err := decodeJSON(params, &updateParams); err != nil {
		// Log error but don't fail - notifications are fire-and-forget
		return
	}

	// Handle resource updated notification
	// In a real implementation, you might notify subscribers about the update
}

func (s *MCP) handlePromptsListChanged() {
	// Handle prompts list changed notification
	// In a real implementation, you might update caches or notify other components
}

func (s *MCP) handleLogMessage(params json.RawMessage) {
	var logParams LogMessageParams
	if err := decodeJSON(params, &logParams); err != nil {
		// Log error but don't fail - notifications are fire-and-forget
		return
	}

	// Handle log message notification
	// In a real implementation, you might log this message or forward it
}
