package mcp

import "encoding/json"

type MCP struct {
	Tools Tools
}

func New() *MCP {
	return &MCP{}
}

func (s *MCP) handleInitialize(id any, params json.RawMessage) JSONRPCResponse {
	var initParams InitializeParams
	if err := json.Unmarshal(params, &initParams); err != nil {
		return s.createErrorResponse(id, -32602, "Invalid params")
	}

	result := InitializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: Capabilities{
			Tools: &ToolsCapability{
				ListChanged: false,
			},
			Resources: &ResourcesCapability{
				Subscribe:   false,
				ListChanged: false,
			},
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
