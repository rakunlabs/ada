package mcp

import (
	"encoding/json"
	"net/http"
)

// HTTP handler for MCP requests
func (s *MCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	// Handle preflight OPTIONS request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		errorResp := s.createErrorResponse(nil, -32700, "Parse error")
		json.NewEncoder(w).Encode(errorResp)
		return
	}

	response := s.handleRequest(request)
	json.NewEncoder(w).Encode(response)
}

func (s *MCP) handleRequest(request JSONRPCRequest) JSONRPCResponse {
	switch request.Method {
	case "initialize":
		if request.Params != nil {
			paramsBytes, _ := json.Marshal(request.Params)
			return s.handleInitialize(request.ID, paramsBytes)
		} else {
			return s.createErrorResponse(request.ID, -32602, "Missing params")
		}
	case "tools/list":
		return s.handleToolsList(request.ID)
	case "tools/call":
		if request.Params != nil {
			paramsBytes, _ := json.Marshal(request.Params)
			return s.handleToolsCall(request.ID, paramsBytes)
		} else {
			return s.createErrorResponse(request.ID, -32602, "Missing params")
		}
	case "resources/list":
		return s.handleResourcesList(request.ID)
	case "resources/read":
		if request.Params != nil {
			paramsBytes, _ := json.Marshal(request.Params)
			return s.handleResourcesRead(request.ID, paramsBytes)
		} else {
			return s.createErrorResponse(request.ID, -32602, "Missing params")
		}
	default:
		return s.createErrorResponse(request.ID, -32601, "Method not found: "+request.Method)
	}
}
