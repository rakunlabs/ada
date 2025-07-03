package mcp

import "encoding/json"

func (s *MCP) handleResourcesList(id any) JSONRPCResponse {
	resources := []Resource{
		{
			URI:         "config://server-info",
			Name:        "Server Information",
			Description: "Information about this MCP server",
			MimeType:    "application/json",
		},
		{
			URI:         "data://sample-text",
			Name:        "Sample Text",
			Description: "A sample text resource",
			MimeType:    "text/plain",
		},
	}

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

	if err := json.Unmarshal(params, &readParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	var content any
	var mimeType string

	switch readParams.URI {
	case "config://server-info":
		content = map[string]any{
			"name":    "example-go-http-server",
			"version": "1.0.0",
			"port":    8080,
			"capabilities": []string{
				"tools",
				"resources",
			},
		}
		mimeType = "application/json"
	case "data://sample-text":
		content = "This is a sample text resource served by the MCP HTTP server.\nIt can contain multiple lines and various content."
		mimeType = "text/plain"
	default:
		return s.createErrorResponse(id, -32602, "Resource not found: "+readParams.URI)
	}

	result := map[string]any{
		"contents": []map[string]any{
			{
				"uri":      readParams.URI,
				"mimeType": mimeType,
			},
		},
	}

	// Add content based on type
	if str, ok := content.(string); ok {
		result["contents"].([]map[string]any)[0]["text"] = str
	} else {
		// For JSON content, convert to text
		jsonBytes, _ := json.MarshalIndent(content, "", "  ")
		result["contents"].([]map[string]any)[0]["text"] = string(jsonBytes)
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}
