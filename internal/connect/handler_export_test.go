package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

func TestExportMyData_AuthRequired(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.ExportMyData(ctx, connect.NewRequest(&identitypb.ExportMyDataRequest{})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("ExportMyData unauth = %v, want Unauthenticated", connectCodeOf(err))
	}
}

func TestExportMyData_HappyPath(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	const farFuture = int64(9_000_000_000_000)
	u := h.repo.seedUser(&service.User{
		Email: "export@e.com", Name: "Exporter", Role: "member",
		Status: service.StatusActive, PasswordHash: "hash-not-exported",
	})

	h.db.addRefreshToken("sess-1", u.ID, farFuture)
	h.db.addPasskey("pk-1", u.ID, "cred-1", "My Laptop")
	if err := h.repo.CreateOAuthIdentity(ctx, &service.OAuthIdentity{
		UserID: u.ID, Provider: "google", ProviderUserID: "g-1",
		EmailAtLinkTime: "export@e.com", CreatedAt: 100,
	}); err != nil {
		t.Fatalf("CreateOAuthIdentity: %v", err)
	}
	if _, err := h.repo.CreateTotpCredential(ctx, &service.TotpCredRecord{
		UserID: u.ID, SecretEncrypted: "totp-secret", Verified: true,
	}); err != nil {
		t.Fatalf("CreateTotpCredential: %v", err)
	}
	if _, err := h.repo.CreateAuditEvent(ctx, &service.AuditEvent{
		EventType: "login_success", ActorUserID: u.ID, TargetUserID: u.ID, Success: true, CreatedAt: 100,
	}); err != nil {
		t.Fatalf("CreateAuditEvent: %v", err)
	}

	resp, err := h.client.ExportMyData(ctx, authedReq(connect.NewRequest(&identitypb.ExportMyDataRequest{}), u.ID))
	if err != nil {
		t.Fatalf("ExportMyData: %v", err)
	}
	msg := resp.Msg

	if msg.GetFormatVersion() != service.ExportFormatVersion {
		t.Errorf("format_version = %d, want %d", msg.GetFormatVersion(), service.ExportFormatVersion)
	}
	if msg.GetExportedAtMs() <= 0 {
		t.Errorf("exported_at_ms = %d, want > 0", msg.GetExportedAtMs())
	}
	if msg.GetUser() == nil || msg.GetUser().GetEmail() != "export@e.com" {
		t.Fatalf("user = %#v, want the caller", msg.GetUser())
	}
	if len(msg.GetSessions()) != 1 {
		t.Errorf("sessions = %d, want 1", len(msg.GetSessions()))
	}
	if len(msg.GetPasskeys()) != 1 || msg.GetPasskeys()[0].GetCredentialId() != "cred-1" {
		t.Errorf("passkeys = %#v, want cred-1", msg.GetPasskeys())
	}
	if len(msg.GetLinkedIdentities()) != 1 || msg.GetLinkedIdentities()[0].GetProvider() != "google" {
		t.Errorf("linked_identities = %#v, want google", msg.GetLinkedIdentities())
	}
	if !msg.GetTotpEnabled() {
		t.Error("totp_enabled = false, want true")
	}
	if len(msg.GetAuditEvents()) != 1 || msg.GetAuditEvents()[0].GetEventType() != "login_success" {
		t.Errorf("audit_events = %#v, want the login event", msg.GetAuditEvents())
	}
}
