package mcp

import (
	"encoding/json"
	"net/http"
)

// Health check endpoint
func (s *MCP) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := HealthCheckResponse{
		Status:  "healthy",
		Server:  "mcp-go-server",
		Version: "1.0.0",
	}

	json.NewEncoder(w).Encode(response)
}
