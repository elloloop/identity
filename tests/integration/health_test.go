//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestHealth_ReturnsOK verifies that GET /health on the running
// service returns 200 with the documented JSON body. This is the
// shape Azure Container Apps and ALB-style probes rely on.
func TestHealth_ReturnsOK(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	resp, err := h.HTTP.Get(h.BaseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body %q: %v", body, err)
	}
	if got["status"] != "ok" {
		t.Fatalf("body = %v, want status=ok", got)
	}
}

// TestHealth_HealthzAlias confirms /healthz is treated identically to
// /health (different probe vendors prefer different paths).
func TestHealth_HealthzAlias(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	resp, err := h.HTTP.Get(h.BaseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
