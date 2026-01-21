package mcp

import (
	"encoding/json"
	"sync"
)

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type Tools struct {
	list     []Tool
	handlers map[string]ToolHandler
	m        sync.RWMutex
}

func (t *Tools) Add(tool Tool, handler ToolHandler) {
	t.m.Lock()
	defer t.m.Unlock()

	t.list = append(t.list, tool)
	if handler != nil {
		t.handlers[tool.Name] = handler
	}
}

func (t *Tools) GetHandler(name string) ToolHandler {
	t.m.RLock()
	defer t.m.RUnlock()
	return t.handlers[name]
}

func (t *Tools) List() []Tool {
	t.m.RLock()
	defer t.m.RUnlock()
	return append([]Tool(nil), t.list...)
}

func (s *MCP) handleToolsList(id any) JSONRPCResponse {
	tools := s.Tools.List()

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

	if err := decodeJSON(params, &callParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	// Get the handler for this tool
	handler := s.Tools.GetHandler(callParams.Name)
	if handler == nil {
		return s.createErrorResponse(id, -32601, "Unknown tool: "+callParams.Name)
	}

	// Call the handler
	result, err := handler(callParams.Arguments)
	if err != nil {
		return s.createErrorResponse(id, -32602, "Tool execution error: "+err.Error())
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}
