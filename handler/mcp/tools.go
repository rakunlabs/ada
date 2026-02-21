package mcp

import (
	"encoding/json"
)

func (s *MCP) handleToolsList(id any) JSONRPCResponse {
	tools := s.Tools.List()

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolsListResult{
			Tools: tools,
		},
	}
}

func (s *MCP) handleToolsCall(id any, params json.RawMessage) JSONRPCResponse {
	var callParams ToolCallParams
	if err := decodeJSON(params, &callParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	// Get the handler for this tool
	handler := s.Tools.GetHandler(callParams.Name)
	if handler == nil {
		return s.createErrorResponse(id, -32602, "Unknown tool: "+callParams.Name)
	}

	// Call the handler
	result, err := handler(callParams.Arguments)
	if err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result:  NewToolCallErrorResult("Tool execution error: " + err.Error()),
		}
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}
