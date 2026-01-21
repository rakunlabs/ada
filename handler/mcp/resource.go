package mcp

import "encoding/json"

func (s *MCP) handleResourcesList(id any) JSONRPCResponse {
	resources := s.Resources.List()

	result := map[string]any{
		"resources": resources,
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handleResourcesRead(id any, params json.RawMessage) JSONRPCResponse {
	var readParams struct {
		URI string `json:"uri"`
	}

	if err := decodeJSON(params, &readParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	// Get the handler for this resource
	handler := s.Resources.GetHandler(readParams.URI)
	if handler == nil {
		return s.createErrorResponse(id, -32602, "Resource not found: "+readParams.URI)
	}

	// Call the handler
	content, err := handler(readParams.URI)
	if err != nil {
		return s.createErrorResponse(id, -32603, "Resource read error: "+err.Error())
	}

	result := map[string]any{
		"contents": []map[string]any{
			{
				"uri": readParams.URI,
			},
		},
	}

	// Add content based on type
	if str, ok := content.(string); ok {
		result["contents"].([]map[string]any)[0]["text"] = str
		result["contents"].([]map[string]any)[0]["mimeType"] = "text/plain"
	} else {
		// For JSON content, convert to text
		jsonBytes, _ := json.MarshalIndent(content, "", "  ")
		result["contents"].([]map[string]any)[0]["text"] = string(jsonBytes)
		result["contents"].([]map[string]any)[0]["mimeType"] = "application/json"
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *MCP) handlePing(id any) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  map[string]any{"status": "pong"},
	}
}
