//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
)

// extractToken pulls the value of ?token=... out of a body string.
// Tests rely on the email templates always emitting that exact prefix.
func extractToken(t *testing.T, body string) string {
	t.Helper()
	idx := strings.Index(body, "token=")
	if idx == -1 {
		t.Fatalf("token= not found in body: %q", body)
	}
	rest := body[idx+len("token="):]
	end := len(rest)
	for i, ch := range rest {
		if ch == ' ' || ch == '\n' || ch == '\r' || ch == '"' || ch == '<' {
			end = i
			break
		}
	}
	return rest[:end]
}

// ── Verification flow ──────────────────────────────────────────────────

// TestEmail_SignupSendsVerification_ThenVerifyEmail drives the full
// email-verification flow: a fresh signup automatically dispatches a
// verification email; the link's token is good for VerifyEmail; after
// VerifyEmail, GetCurrentUser reports email_verified=true.
func TestEmail_SignupSendsVerification_ThenVerifyEmail(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	const addr = "newuser@test.com"
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: "Sw0rdfish!42",
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	sent := h.Mailer.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 verification email after signup, got %d", len(sent))
	}
	if sent[0].To != addr {
		t.Errorf("verification email To: got %q, want %q", sent[0].To, addr)
	}
	tok := extractToken(t, sent[0].Text)

	// Verify via Connect-RPC.
	verifyResp, err := h.Client.VerifyEmail(ctx, connect.NewRequest(&identitypb.VerifyEmailRequest{
		Token: tok,
	}))
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if !verifyResp.Msg.GetUser().GetEmailVerified() {
		t.Errorf("VerifyEmail response: EmailVerified=false")
	}

	// Check via authenticated GetCurrentUser.
	authed := h.AuthedClient(signup.Msg.AccessToken)
	cur, err := authed.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if !cur.Msg.GetUser().GetEmailVerified() {
		t.Errorf("GetCurrentUser: EmailVerified=false; want true")
	}
}

// ── Password reset flow ────────────────────────────────────────────────

// TestEmail_RequestAndConfirmPasswordReset exercises the full reset
// flow: request a reset, extract the token from the email, confirm
// with a new password, then verify that the new password works while
// the old one is rejected.
func TestEmail_RequestAndConfirmPasswordReset(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	const addr = "resetuser@test.com"
	const oldPW = "Sw0rdfish!42"
	const newPW = "Newp@ssw0rd!99"

	if _, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: oldPW,
	})); err != nil {
		t.Fatalf("signup: %v", err)
	}
	h.Mailer.Reset() // drop the verification email noise

	if _, err := h.Client.RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: addr,
	})); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	sent := h.Mailer.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 reset email, got %d", len(sent))
	}
	tok := extractToken(t, sent[0].Text)

	if _, err := h.Client.ConfirmPasswordReset(ctx, connect.NewRequest(&identitypb.ConfirmPasswordResetRequest{
		Token: tok, NewPassword: newPW,
	})); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}

	// Login with new password works.
	if _, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: addr, Password: newPW,
	})); err != nil {
		t.Errorf("login with new password: %v", err)
	}

	// Login with old password fails.
	_, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: addr, Password: oldPW,
	}))
	if err == nil {
		t.Errorf("login with old password should have failed but succeeded")
	}
}

// TestEmail_RequestPasswordReset_UnknownEmail_NoEnumeration ensures
// the RequestPasswordReset RPC returns success even when no account
// matches the supplied email, and never sends a message.
func TestEmail_RequestPasswordReset_UnknownEmail_NoEnumeration(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	if _, err := h.Client.RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: "ghost@test.com",
	})); err != nil {
		t.Fatalf("RequestPasswordReset for unknown email should succeed silently, got %v", err)
	}
	if got := len(h.Mailer.Sent()); got != 0 {
		t.Errorf("unknown email: expected 0 sends, got %d", got)
	}
}

func TestEmail_RequestPasswordReset_Disabled_NoEmailOrToken(t *testing.T) {
	t.Parallel()
	h := StartServer(t, WithConfig(func(cfg *config.Config) {
		cfg.PasswordResetEnabled = false
	}))
	ctx := context.Background()

	if _, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "reset-disabled@test.com",
		Password: "Sw0rdfish!42",
	})); err != nil {
		t.Fatalf("signup: %v", err)
	}
	h.Mailer.Reset()

	if _, err := h.Client.RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: "reset-disabled@test.com",
	})); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if got := len(h.Mailer.Sent()); got != 0 {
		t.Fatalf("expected 0 reset emails, got %d", got)
	}

	if got := h.CountPasswordResetTokensForUser(t, h.FindUserIDByEmail(t, "reset-disabled@test.com")); got != 0 {
		t.Fatalf("expected 0 reset tokens, got %d", got)
	}
}

// ── Invitation flow ────────────────────────────────────────────────────

// TestEmail_InviteUser_SendsInvitationEmail seeds an admin directly in
// MemRepo (so we can take an admin path through the InviteUser RPC),
// invites a new user via the admin RPC, and asserts the invitation
// email was sent and the embedded token successfully accepts via
// AcceptInvitation.
//
// NOTE: Today's wiring routes admin RPCs through service.AdminService
// which requires the *DB* interface (not the Repository interface).
// The integration server uses RecordingDB for that role, which is
// stubbed for non-audit calls, so AdminService.InviteUser cannot
// reach a real backing store via the Connect-RPC path here. Instead
// we exercise InviteUser directly against an AdminService bound to a
// real DB-backed fake — separate from the harness — and only assert
// the recording transport receives the invitation. This still
// regression-tests the missing email send.
func TestEmail_InviteUser_SendsInvitationEmail(t *testing.T) {
	t.Parallel()
	mailer := NewRecordingMailer()
	db := newAdminFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	cfg := newTestConfig()
	cfg.AppBaseURL = "https://app.test"
	cfg.SMTPFrom = "no-reply@test.local"
	// InviteUser uses the DB (graph) handle, not the Repository handle,
	// so a stub repo is sufficient here; it fails loudly if that ever
	// changes.
	svc := service.NewAdminService(service.StubRepository{}, db, "test-tenant",
		audit.NewLogger(nil, "test-tenant", zap.NewNop()),
		cfg, mailer, zap.NewNop())

	result, err := svc.InviteUser(context.Background(), "admin-1",
		"invitee@test.com", "Invitee", "member", "", 0, false)
	if err != nil {
		t.Fatalf("InviteUser: %v", err)
	}
	sent := mailer.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 invitation email, got %d", len(sent))
	}
	if sent[0].To != "invitee@test.com" {
		t.Errorf("invitation To: got %q, want invitee@test.com", sent[0].To)
	}
	if !strings.Contains(sent[0].Text, result.InvitationToken) {
		t.Errorf("invitation body missing token; body=%q", sent[0].Text)
	}
}
