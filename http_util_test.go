package letsdebug

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestHTTPTimeout(t *testing.T) {
	// Test that HTTP requests respect the timeout
	start := time.Now()

	// Create a mock server that delays for longer than our timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep for longer than our 3-second timeout
		time.Sleep(4 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Extract the IP from the test server
	addr := server.Listener.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("Failed to split address: %v", err)
	}

	// Parse the IP
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("Failed to parse IP: %s", host)
	}

	// Create a scan context with the test server's hostname
	ctx := &scanContext{
		httpRequestPath:    "test",
		httpExpectResponse: "",
		httpDialPort:       port,
	}

	// Test the checkHTTP function
	result, problem := checkHTTP(ctx, "test.example.com", ip)

	duration := time.Since(start)

	// The request should timeout within a reasonable time (less than 4 seconds)
	if duration > 4*time.Second {
		t.Errorf("HTTP request took too long: %v, expected timeout within 4 seconds", duration)
	}

	// We should get a timeout error
	if problem.IsZero() {
		t.Error("Expected a timeout problem, but got none")
	}

	// The result should be empty due to timeout
	if !result.IsZero() {
		t.Errorf("Expected empty result due to timeout, but got: %+v", result)
	}

	t.Logf("HTTP timeout test completed in %v", duration)
}

func TestHTTPTimeoutWithSlowServer(t *testing.T) {
	// Test with a server that actually takes time to respond
	start := time.Now()

	// Create a server that delays for 5 seconds (longer than our 3-second timeout)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("delayed response")); err != nil {
			// Log error but don't fail the test
			t.Logf("write error: %v", err)
		}
	}))
	defer server.Close()

	// Extract the IP from the test server
	addr := server.Listener.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("Failed to split address: %v", err)
	}

	// Parse the IP
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("Failed to parse IP: %s", host)
	}

	// Create a scan context
	ctx := &scanContext{
		httpRequestPath:    "test",
		httpExpectResponse: "",
		httpDialPort:       port,
	}

	// Test the checkHTTP function
	result, problem := checkHTTP(ctx, "test.example.com", ip)

	duration := time.Since(start)

	// The request should timeout within a reasonable time (less than 5 seconds)
	if duration > 5*time.Second {
		t.Errorf("HTTP request took too long: %v, expected timeout within 5 seconds", duration)
	}

	// We should get a timeout error
	if problem.IsZero() {
		t.Error("Expected a timeout problem, but got none")
	}

	// The result should be empty due to timeout
	if !result.IsZero() {
		t.Errorf("Expected empty result due to timeout, but got: %+v", result)
	}

	t.Logf("Slow server timeout test completed in %v", duration)
}

func TestHTTPTimeoutWithRealDomain(t *testing.T) {
	// Test timeout behavior with a real domain that might be slow
	// This test verifies that our timeout fix actually works in practice

	if os.Getenv("LETSDEBUG_INTEGRATION") == "" {
		t.Skip("integration test: set LETSDEBUG_INTEGRATION=1 to run")
	}

	// Use a domain that we know can be slow (like logerit.com from the original issue)
	domain := "logerit.com"

	// Resolve the domain to get an IP
	ips, err := net.LookupIP(domain)
	if err != nil {
		t.Skipf("Skipping test - cannot resolve %s: %v", domain, err)
	}

	if len(ips) == 0 {
		t.Skipf("Skipping test - no IPs found for %s", domain)
	}

	ip := ips[0]
	t.Logf("Testing timeout with domain %s at IP %s", domain, ip)

	// Create a scan context
	ctx := &scanContext{
		httpRequestPath:    "test",
		httpExpectResponse: "",
	}

	start := time.Now()

	// Test the checkHTTP function
	_, problem := checkHTTP(ctx, domain, ip)

	duration := time.Since(start)

	// The request should complete within a reasonable time (less than 4 seconds)
	// If it takes longer, it means our timeout isn't working
	if duration > 4*time.Second {
		t.Errorf("HTTP request took too long: %v, expected completion within 4 seconds due to timeout", duration)
	}

	// We should get a timeout problem or some other error
	if problem.IsZero() {
		t.Logf("Request completed successfully in %v (this might happen if the domain is actually fast)", duration)
	} else {
		t.Logf("Request failed with problem: %s in %v", problem.Name, duration)
	}

	t.Logf("Real domain timeout test completed in %v", duration)
}
