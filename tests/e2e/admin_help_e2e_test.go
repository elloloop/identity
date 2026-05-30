//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"
)

// TestE2E_AdminHelpFlow drives the admin help request creation, listing, and resolution.
func TestE2E_AdminHelpFlow(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	// 1. Request Admin Help (exempt from auth, publicly accessible)
	resp, status := h.rpcCall(t, "RequestAdminHelp", map[string]any{
		"email":  "helpme@example.com",
		"reason": "Locked out of my 2FA TOTP device.",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("RequestAdminHelp status=%d, body=%v", status, resp)
	}

	// 2. Seed admin and login
	adminEmail := "admin-help@example.com"
	h.SeedUser(t, adminEmail, "Admin User", "admin", "active", goodPassword)
	at, _ := h.Login(t, adminEmail, goodPassword)

	// 3. List Help Requests
	resp, status = h.rpcCall(t, "ListHelpRequests", map[string]any{
		"statusFilter": "HELP_REQUEST_STATUS_PENDING",
		"limit":        10,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("ListHelpRequests status=%d, body=%v", status, resp)
	}
	requests, _ := resp["requests"].([]any)
	if len(requests) != 1 {
		t.Fatalf("expected 1 pending help request, got %d", len(requests))
	}
	firstReq, _ := requests[0].(map[string]any)
	reqID, _ := firstReq["id"].(string)
	if reqID == "" {
		t.Fatalf("expected non-empty help request ID")
	}
	if firstReq["email"] != "helpme@example.com" {
		t.Errorf("request email = %v, want 'helpme@example.com'", firstReq["email"])
	}

	// 4. Resolve Help Request
	resp, status = h.rpcCall(t, "ResolveHelpRequest", map[string]any{
		"requestId":       reqID,
		"resolutionNotes": "Verified identity via phone and reset 2FA.",
	}, at)
	if status != http.StatusOK {
		t.Fatalf("ResolveHelpRequest status=%d, body=%v", status, resp)
	}

	// 5. Verify it is no longer pending (with retry for eventual consistency)
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, _ = h.rpcCall(t, "ListHelpRequests", map[string]any{
			"statusFilter": "HELP_REQUEST_STATUS_PENDING",
			"limit":        10,
		}, at)
		requests, _ = resp["requests"].([]any)
		if len(requests) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 0 pending help requests, got %d", len(requests))
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 6. Verify it is listed under resolved status (with retry for eventual consistency)
	deadline = time.Now().Add(3 * time.Second)
	for {
		resp, _ = h.rpcCall(t, "ListHelpRequests", map[string]any{
			"statusFilter": "HELP_REQUEST_STATUS_RESOLVED",
			"limit":        10,
		}, at)
		requests, _ = resp["requests"].([]any)
		if len(requests) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 1 resolved help request, got %d", len(requests))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
