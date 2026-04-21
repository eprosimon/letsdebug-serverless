package handler

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"

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

const (
	maxRequestBodyBytes = 8 * 1024
)

// Handler is the exported function that Vercel expects
func Handler(w http.ResponseWriter, r *http.Request) {
	setBaseHeaders(w)

	if r.Method == "OPTIONS" {
		if !isAllowedOrigin(r) {
			writeJSONError(w, http.StatusForbidden, "Origin not allowed")
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !isAllowedOrigin(r) {
		writeJSONError(w, http.StatusForbidden, "Origin not allowed")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	defer r.Body.Close()

	var req DebugRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		var syntaxErr *json.SyntaxError
		var unmarshalTypeErr *json.UnmarshalTypeError
		switch {
		case errors.As(err, &maxBytesErr):
			writeJSONError(w, http.StatusRequestEntityTooLarge, "Request body too large")
		case errors.As(err, &syntaxErr):
			writeJSONError(w, http.StatusBadRequest, "Malformed JSON")
		case errors.As(err, &unmarshalTypeErr):
			writeJSONError(w, http.StatusBadRequest, "Invalid field types in JSON")
		case errors.Is(err, io.EOF):
			writeJSONError(w, http.StatusBadRequest, "Request body is empty")
		default:
			writeJSONError(w, http.StatusBadRequest, "Invalid JSON request body")
		}
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "Only one JSON object is allowed")
		return
	}

	req.Domain = normalizeDomain(req.Domain)
	if !isValidDomainRequest(req.Domain) {
		writeJSONError(w, http.StatusBadRequest, "A valid domain is required")
		return
	}

	method, err := parseValidationMethod(req.Method)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Run the debug check
	problems, err := letsdebug.Check(req.Domain, method)

	response := DebugResponse{
		Problems: problems,
	}

	if err != nil {
		response.Error = "Debug check failed"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func setBaseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Vary", "Origin")
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(DebugResponse{
		Problems: []letsdebug.Problem{},
		Error:    message,
	})
}

func normalizeDomain(domain string) string {
	return strings.TrimSpace(strings.ToLower(domain))
}

func isValidDomainRequest(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	if strings.Contains(domain, "://") ||
		strings.Contains(domain, "/") ||
		strings.Contains(domain, " ") ||
		strings.Contains(domain, "@") ||
		strings.HasPrefix(domain, ".") ||
		strings.HasSuffix(domain, ".") {
		return false
	}
	if ip := net.ParseIP(domain); ip != nil {
		return false
	}
	return true
}

func parseValidationMethod(raw string) (letsdebug.ValidationMethod, error) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "", "http-01":
		return letsdebug.HTTP01, nil
	case "dns-01":
		return letsdebug.DNS01, nil
	case "tls-alpn-01":
		return letsdebug.TLSALPN01, nil
	default:
		return "", errors.New("Unsupported validation method")
	}
}

func isAllowedOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil || parsedOrigin.Host == "" || parsedOrigin.Scheme == "" {
		return false
	}

	requestHost := strings.TrimSpace(strings.ToLower(r.Host))
	originHost := strings.TrimSpace(strings.ToLower(parsedOrigin.Host))
	if requestHost == "" || originHost != requestHost {
		return false
	}

	return parsedOrigin.Scheme == requestScheme(r)
}

func requestScheme(r *http.Request) string {
	if forwardedProto := r.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
		return strings.ToLower(strings.TrimSpace(strings.Split(forwardedProto, ",")[0]))
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
