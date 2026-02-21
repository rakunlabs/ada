package mcp

import (
	"encoding/json"
)

// ToolHandler represents a function that handles tool calls.
type ToolHandler func(args map[string]any) (ToolCallResult, error)

// ResourceHandler represents a function that provides resource content.
type ResourceHandler func(uri string) (ResourceContent, error)

// PromptHandler represents a function that generates prompt content.
type PromptHandler func(args map[string]string) (GetPromptResult, error)

// CompletionHandler represents a function that provides completion suggestions.
type CompletionHandler func(req CompleteRequest) (CompletionValues, error)

type MCP struct {
	Tools              Tools
	Resources          Resources
	ResourceTemplates  ResourceTemplates
	Prompts            Prompts
	CompletionHandlers CompletionHandlers

	ServerName    string
	ServerVersion string
	Instructions  string
}

func New() *MCP {
	mcp := &MCP{
		Tools: Tools{
			handlers: make(map[string]ToolHandler),
		},
		Resources: Resources{
			handlers: make(map[string]ResourceHandler),
		},
		ResourceTemplates: ResourceTemplates{},
		Prompts: Prompts{
			handlers: make(map[string]PromptHandler),
		},
		CompletionHandlers: CompletionHandlers{
			handlers: make(map[string]CompletionHandler),
		},
		ServerName:    "mcp-go-server",
		ServerVersion: "1.0.0",
	}

	return mcp
}

func (s *MCP) handleInitialize(id any, params json.RawMessage) JSONRPCResponse {
	var initParams InitializeParams
	if err := decodeJSON(params, &initParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	result := InitializeResult{
		ProtocolVersion: "2025-11-25",
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
			Name:    s.ServerName,
			Version: s.ServerVersion,
		},
		Instructions: s.Instructions,
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handleInitialized() {
	// Client has finished initialization, server can now send requests.
	// This is a notification, so no response is sent.
}

func (s *MCP) handlePromptsList(id any) JSONRPCResponse {
	prompts := s.Prompts.List()

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: PromptsListResult{
			Prompts: prompts,
		},
	}
}

func (s *MCP) handlePromptsGet(id any, params json.RawMessage) JSONRPCResponse {
	var getParams PromptsGetParams
	if err := decodeJSON(params, &getParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	handler := s.Prompts.GetHandler(getParams.Name)
	if handler == nil {
		return s.createErrorResponse(id, -32602, "Unknown prompt: "+getParams.Name)
	}

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
	templates := s.ResourceTemplates.List()

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ResourceTemplatesListResult{
			ResourceTemplates: templates,
		},
	}
}

func (s *MCP) handleResourcesSubscribe(id any, params json.RawMessage) JSONRPCResponse {
	var subscribeParams SubscribeRequest
	if err := decodeJSON(params, &subscribeParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  EmptyResult{},
	}
}

func (s *MCP) handleResourcesUnsubscribe(id any, params json.RawMessage) JSONRPCResponse {
	var unsubscribeParams UnsubscribeRequest
	if err := decodeJSON(params, &unsubscribeParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  EmptyResult{},
	}
}

func (s *MCP) handleCompletionComplete(id any, params json.RawMessage) JSONRPCResponse {
	var completeParams CompleteRequest
	if err := decodeJSON(params, &completeParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	// Build the reference key to look up a registered handler.
	// For ref/prompt use the name, for ref/resource use the URI.
	var refKey string
	switch completeParams.Ref.Type {
	case "ref/prompt":
		refKey = "prompt:" + completeParams.Ref.Name
	case "ref/resource":
		refKey = "resource:" + completeParams.Ref.URI
	default:
		refKey = completeParams.Ref.Type + ":" + completeParams.Ref.Name
	}

	handler := s.CompletionHandlers.GetHandler(refKey)
	if handler == nil {
		// No handler registered, return empty completions.
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: CompleteResult{
				Completion: CompletionValues{
					Values:  []string{},
					HasMore: false,
				},
			},
		}
	}

	values, err := handler(completeParams)
	if err != nil {
		return s.createErrorResponse(id, -32603, "Completion error: "+err.Error())
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: CompleteResult{
			Completion: values,
		},
	}
}

func (s *MCP) handleLoggingSetLevel(id any, params json.RawMessage) JSONRPCResponse {
	var levelParams SetLevelRequest
	if err := decodeJSON(params, &levelParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  EmptyResult{},
	}
}

func (s *MCP) handlePing(id any) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  EmptyResult{},
	}
}

// /////////////////////////////////////////////////////////////
// Public API methods

// AddTool registers a tool and its handler.
func (s *MCP) AddTool(tool Tool, handler ToolHandler) {
	s.Tools.Add(tool, handler)
}

// AddResource registers a resource and its handler.
func (s *MCP) AddResource(resource Resource, handler ResourceHandler) {
	s.Resources.Add(resource, handler)
}

// AddResourceTemplate registers a resource template.
func (s *MCP) AddResourceTemplate(template ResourceTemplate) {
	s.ResourceTemplates.Add(template)
}

// AddPrompt registers a prompt and its handler.
func (s *MCP) AddPrompt(prompt Prompt, handler PromptHandler) {
	s.Prompts.Add(prompt, handler)
}

// AddCompletionHandler registers a completion handler for a reference key.
// Use "prompt:<name>" for prompt completions and "resource:<uri>" for resource completions.
func (s *MCP) AddCompletionHandler(refKey string, handler CompletionHandler) {
	s.CompletionHandlers.Add(refKey, handler)
}

// /////////////////////////////////////////////////////////////
// Notification handlers

func (s *MCP) handleToolsListChanged() {
	// Handle tools list changed notification.
}

func (s *MCP) handleResourcesListChanged() {
	// Handle resources list changed notification.
}

func (s *MCP) handleResourceUpdated(params json.RawMessage) {
	var updateParams ResourceUpdatedNotification
	if err := decodeJSON(params, &updateParams); err != nil {
		return
	}
	// Handle resource updated notification.
}

func (s *MCP) handlePromptsListChanged() {
	// Handle prompts list changed notification.
}

func (s *MCP) handleLogMessage(params json.RawMessage) {
	var logParams LogMessageParams
	if err := decodeJSON(params, &logParams); err != nil {
		return
	}
	// Handle log message notification.
}

func (s *MCP) handleCancelled(params json.RawMessage) {
	var cancelParams CancelledParams
	if err := decodeJSON(params, &cancelParams); err != nil {
		return
	}
	// Handle cancellation notification.
	// In a real implementation, you would stop processing the cancelled request.
}

func (s *MCP) handleTaskStatusNotification(params json.RawMessage) {
	var taskStatus TaskStatusNotification
	if err := decodeJSON(params, &taskStatus); err != nil {
		return
	}
	// Handle task status notification.
}
