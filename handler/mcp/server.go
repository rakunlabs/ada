package mcp

import (
	"encoding/json"
	"net/http"
)

// HTTP handler for MCP requests
func (s *MCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	// For notifications, don't send a response
	if response.ID == nil && response.Result == nil && response.Error == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	json.NewEncoder(w).Encode(response)
}

func (s *MCP) handleRequest(request JSONRPCRequest) JSONRPCResponse {
	// Handle notifications (no ID, no response expected)
	if request.ID == nil {
		s.handleNotification(request.Method, request.Params)
		return JSONRPCResponse{} // Empty response for notifications
	}

	// Handle requests (with ID, response expected)
	switch request.Method {
	case "initialize":
		if request.Params != nil {
			return s.handleInitialize(request.ID, request.Params)
		}
		return s.createErrorResponse(request.ID, -32602, "Missing params")
	case "tools/list":
		return s.handleToolsList(request.ID)
	case "tools/call":
		if request.Params != nil {
			return s.handleToolsCall(request.ID, request.Params)
		}
		return s.createErrorResponse(request.ID, -32602, "Missing params")
	case "resources/list":
		return s.handleResourcesList(request.ID)
	case "resources/read":
		if request.Params != nil {
			return s.handleResourcesRead(request.ID, request.Params)
		}
		return s.createErrorResponse(request.ID, -32602, "Missing params")
	case "resources/templates/list":
		return s.handleResourcesTemplatesList(request.ID)
	case "resources/subscribe":
		if request.Params != nil {
			return s.handleResourcesSubscribe(request.ID, request.Params)
		}
		return s.createErrorResponse(request.ID, -32602, "Missing params")
	case "resources/unsubscribe":
		if request.Params != nil {
			return s.handleResourcesUnsubscribe(request.ID, request.Params)
		}
		return s.createErrorResponse(request.ID, -32602, "Missing params")
	case "prompts/list":
		return s.handlePromptsList(request.ID)
	case "prompts/get":
		if request.Params != nil {
			return s.handlePromptsGet(request.ID, request.Params)
		}
		return s.createErrorResponse(request.ID, -32602, "Missing params")
	case "completion/complete":
		if request.Params != nil {
			return s.handleCompletionComplete(request.ID, request.Params)
		}
		return s.createErrorResponse(request.ID, -32602, "Missing params")
	case "logging/setLevel":
		if request.Params != nil {
			return s.handleLoggingSetLevel(request.ID, request.Params)
		}
		return s.createErrorResponse(request.ID, -32602, "Missing params")
	case "ping":
		return s.handlePing(request.ID)
	default:
		return s.createErrorResponse(request.ID, -32601, "Method not found: "+request.Method)
	}
}

func (s *MCP) handleNotification(method string, params json.RawMessage) {
	switch method {
	case "notifications/initialized":
		s.handleInitialized()
	case "notifications/tools/list_changed":
		s.handleToolsListChanged()
	case "notifications/resources/list_changed":
		s.handleResourcesListChanged()
	case "notifications/resources/updated":
		s.handleResourceUpdated(params)
	case "notifications/prompts/list_changed":
		s.handlePromptsListChanged()
	case "notifications/message":
		s.handleLogMessage(params)
	}
}
