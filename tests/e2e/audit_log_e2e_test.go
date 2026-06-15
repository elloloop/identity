//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"
)

// TestE2E_AuditLog_AuthorizationAndQuerying verifies that only admins can query
// the audit log, and that it successfully records and lists audit events.
func TestE2E_AuditLog_AuthorizationAndQuerying(t *testing.T) {
	requireGraphDB(t)
	t.Parallel()
	h := StartServer(t)

	// 1. Seed member user and admin user
	memberEmail := "member-audit@example.com"
	h.SeedUser(t, memberEmail, "Member User", "member", "active", goodPassword)
	memberAt, _ := h.Login(t, memberEmail, goodPassword)

	adminEmail := "admin-audit@example.com"
	h.SeedUser(t, adminEmail, "Admin User", "admin", "active", goodPassword)
	adminAt, _ := h.Login(t, adminEmail, goodPassword)

	// 2. Member trying to query audit events must be forbidden (non-200)
	resp, status := h.rpcCall(t, "ListAuditEvents", map[string]any{
		"limit": 10,
	}, memberAt)
	if status == http.StatusOK {
		t.Fatalf("ListAuditEvents unexpectedly succeeded for non-admin user: %v", resp)
	}
	code, _ := resp["code"].(string)
	if code != "permission_denied" {
		t.Errorf("ListAuditEvents for member code = %q, want 'permission_denied'", code)
	}

	// 3. Admin queries audit events successfully (should see at least their logins/seeds)
	// We use a retry loop for eventual consistency of audit event writing.
	deadline := time.Now().Add(3 * time.Second)
	var events []any
	for {
		resp, status = h.rpcCall(t, "ListAuditEvents", map[string]any{
			"limit": 50,
		}, adminAt)
		if status == http.StatusOK {
			events, _ = resp["events"].([]any)
			if len(events) > 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected at least 1 audit event for admin, got %d (status=%d, body=%v)", len(events), status, resp)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 4. Verify some details on the returned events
	firstEvent, _ := events[0].(map[string]any)
	eventID, _ := firstEvent["id"].(string)
	if eventID == "" {
		t.Errorf("expected non-empty audit event ID")
	}
	eventType, _ := firstEvent["eventType"].(string)
	if eventType == "" {
		t.Errorf("expected non-empty audit event eventType")
	}
}
