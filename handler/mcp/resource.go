package mcp

import "encoding/json"

func (s *MCP) handleResourcesList(id any) JSONRPCResponse {
	resources := s.Resources.List()

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ResourcesListResult{
			Resources: resources,
		},
	}
}

func (s *MCP) handleResourcesRead(id any, params json.RawMessage) JSONRPCResponse {
	var readParams ResourcesReadParams
	if err := decodeJSON(params, &readParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	handler := s.Resources.GetHandler(readParams.URI)
	if handler == nil {
		return s.createErrorResponse(id, -32002, "Resource not found: "+readParams.URI)
	}

	content, err := handler(readParams.URI)
	if err != nil {
		return s.createErrorResponse(id, -32603, "Resource read error: "+err.Error())
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ResourcesReadResult{
			Contents: []ResourceContent{content},
		},
	}
}
