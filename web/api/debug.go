package handler

import (
	"encoding/json"
	"net/http"

	"github.com/eprosimon/letsdebug-serverless"
)

type DebugRequest struct {
	Domain string `json:"domain"`
	Method string `json:"method"`
}

type DebugResponse struct {
	Problems []letsdebug.Problem `json:"problems"`
	Error    string              `json:"error,omitempty"`
}

// Handler is the exported function that Vercel expects
func Handler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DebugRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}

	// Validate method
	var method letsdebug.ValidationMethod
	switch req.Method {
	case "http-01":
		method = letsdebug.HTTP01
	case "dns-01":
		method = letsdebug.DNS01
	case "tls-alpn-01":
		method = letsdebug.TLSALPN01
	default:
		method = letsdebug.HTTP01 // default to http-01
	}

	// Run the debug check
	problems, err := letsdebug.Check(req.Domain, method)

	response := DebugResponse{
		Problems: problems,
	}

	if err != nil {
		response.Error = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
