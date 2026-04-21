package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerRejectsInvalidOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://localhost/api/debug", strings.NewReader(`{"domain":"example.com","method":"http-01"}`))
	req.Host = "localhost"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Handler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

func TestHandlerRejectsWrongContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://localhost/api/debug", strings.NewReader(`domain=example.com`))
	req.Host = "localhost"
	req.Header.Set("Origin", "https://localhost")
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()

	Handler(rr, req)

	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected status %d, got %d", http.StatusUnsupportedMediaType, rr.Code)
	}
}

func TestHandlerRejectsOversizedBody(t *testing.T) {
	tooLarge := `{"domain":"` + strings.Repeat("a", maxRequestBodyBytes) + `.com","method":"http-01"}`
	req := httptest.NewRequest(http.MethodPost, "https://localhost/api/debug", bytes.NewBufferString(tooLarge))
	req.Host = "localhost"
	req.Header.Set("Origin", "https://localhost")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Handler(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, rr.Code)
	}
}

func TestHandlerRejectsMalformedDomain(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://localhost/api/debug", strings.NewReader(`{"domain":"http://bad domain","method":"http-01"}`))
	req.Host = "localhost"
	req.Header.Set("Origin", "https://localhost")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandlerAllowsSameOriginBeforeValidationMethodCheck(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://localhost/api/debug", strings.NewReader(`{"domain":"example.com","method":"invalid-method"}`))
	req.Host = "localhost"
	req.Header.Set("Origin", "https://localhost")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Unsupported validation method") {
		t.Fatalf("expected unsupported validation method error, got %s", rr.Body.String())
	}
}
