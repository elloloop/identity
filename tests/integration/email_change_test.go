//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
)

// TestEmailChange_FullFlow drives the end-to-end primary-email rotation
// over Connect-RPC. It covers:
//
//   - signup creates a user
//   - RequestEmailChange sends both verify-to-new and notice-to-old emails
//   - the OLD address has no verification token in the body
//   - ConfirmEmailChange succeeds without any auth header (the link click
//     scenario) and updates the user's email
//   - all refresh tokens for the user are revoked after confirm
//   - the user can log in with the new email + same password
func TestEmailChange_FullFlow(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	const oldAddr = "old-primary@test.com"
	const newAddr = "new-primary@test.com"
	const password = "Sw0rdfish!42"

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: oldAddr, Password: password,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	userID := signup.Msg.GetUser().GetId()
	if userID == "" {
		t.Fatalf("signup returned empty user id")
	}
	if got := h.CountRefreshTokensForUser(t, userID); got == 0 {
		t.Fatalf("expected at least one refresh token after signup, got %d", got)
	}
	h.Mailer.Reset() // drop the auto verification email noise

	authed := h.AuthedClient(signup.Msg.GetAccessToken())

	if _, err := authed.RequestEmailChange(ctx, connect.NewRequest(&identitypb.RequestEmailChangeRequest{
		NewEmail: newAddr, CurrentPassword: password,
	})); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}

	sent := h.Mailer.Sent()
	if len(sent) != 2 {
		t.Fatalf("expected 2 emails (verify + notice), got %d", len(sent))
	}

	// Order is: verify-to-new, then notice-to-old.
	verify, notice := sent[0], sent[1]
	if verify.To != newAddr {
		t.Errorf("verify To: got %q want %q", verify.To, newAddr)
	}
	if notice.To != oldAddr {
		t.Errorf("notice To: got %q want %q", notice.To, oldAddr)
	}
	if !strings.Contains(verify.Text, "/auth/confirm-email-change?token=") {
		t.Errorf("verify body missing confirm link: %q", verify.Text)
	}
	if strings.Contains(notice.Text, "token=") {
		t.Errorf("notice body must NOT include the token: %q", notice.Text)
	}
	tok := extractToken(t, verify.Text)

	// ConfirmEmailChange is exempt from auth — call it on the unauth'd
	// client to verify the middleware exemption is wired.
	confirm, err := h.Client.ConfirmEmailChange(ctx, connect.NewRequest(&identitypb.ConfirmEmailChangeRequest{
		Token: tok,
	}))
	if err != nil {
		t.Fatalf("ConfirmEmailChange (no auth): %v", err)
	}
	if confirm.Msg.GetUser().GetEmail() != newAddr {
		t.Errorf("confirm response email: got %q want %q", confirm.Msg.GetUser().GetEmail(), newAddr)
	}
	if !confirm.Msg.GetUser().GetEmailVerified() {
		t.Errorf("confirm response should report email_verified=true")
	}

	// Refresh tokens revoked.
	if got := h.CountRefreshTokensForUser(t, userID); got != 0 {
		t.Errorf("expected 0 refresh tokens after confirm, got %d", got)
	}

	// New email + same password works for login.
	if _, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: newAddr, Password: password,
	})); err != nil {
		t.Errorf("login with new email: %v", err)
	}

	// Old email no longer authenticates.
	if _, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: oldAddr, Password: password,
	})); err == nil {
		t.Errorf("login with old email should fail after rotation")
	}
}

// TestEmailChange_RequiresAuth verifies the auth middleware still
// guards RequestEmailChange (not exempted).
func TestEmailChange_RequiresAuth(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	_, err := h.Client.RequestEmailChange(ctx, connect.NewRequest(&identitypb.RequestEmailChangeRequest{
		NewEmail: "anything@test.com", CurrentPassword: "x",
	}))
	if err == nil {
		t.Fatalf("RequestEmailChange without auth should fail")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeUnauthenticated {
		t.Errorf("got %v (code %v), want unauthenticated", err, connect.CodeOf(err))
	}
}

// TestEmailChange_WrongPassword rejects the request with InvalidArgument /
// Unauthenticated even when the caller is otherwise authenticated.
func TestEmailChange_WrongPassword(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	const addr = "alice-changewrong@test.com"
	const password = "Sw0rdfish!42"

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: password,
	}))
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	h.Mailer.Reset()
	authed := h.AuthedClient(signup.Msg.GetAccessToken())

	_, err = authed.RequestEmailChange(ctx, connect.NewRequest(&identitypb.RequestEmailChangeRequest{
		NewEmail: "another@test.com", CurrentPassword: "WrongPw1!",
	}))
	if err == nil {
		t.Fatalf("wrong password should be rejected")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Errorf("code: got %v want unauthenticated", got)
	}
	if got := len(h.Mailer.Sent()); got != 0 {
		t.Errorf("no emails should be sent on auth failure, got %d", got)
	}
}
