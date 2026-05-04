//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
)

// goodPassword satisfies pkg/passwords.ValidateStrength: ≥8 chars,
// upper, lower, digit, special, and not in the common-password list.
const goodPassword = "Sw0rdfish!42"

// TestPassword_SignupLoginGetCurrentUser drives the canonical
// password-account onboarding flow end-to-end:
//
//  1. PasswordSignup creates the user and returns tokens.
//  2. PasswordLogin with the same credentials succeeds.
//  3. GetCurrentUser, called with the access token, returns the same
//     user identity that was just created.
//
// This confirms the JWT minted at signup is verifiable by the
// AuthMiddleware on a separate request, and that the X-Authenticated-User-Id
// header propagation works through the Connect handler.
func TestPassword_SignupLoginGetCurrentUser(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	const email = "alice@example.com"

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	if signup.Msg.AccessToken == "" {
		t.Fatalf("signup returned empty access token")
	}
	if signup.Msg.RefreshToken == "" {
		t.Fatalf("signup returned empty refresh token")
	}
	if got := signup.Msg.GetUser().GetEmail(); got != email {
		t.Fatalf("signup email = %q, want %q", got, email)
	}
	signupUserID := signup.Msg.GetUser().GetId()

	// Login with the same credentials.
	login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordLogin: %v", err)
	}
	if login.Msg.AccessToken == "" {
		t.Fatalf("login returned empty access token")
	}
	if got := login.Msg.GetUser().GetId(); got != signupUserID {
		t.Fatalf("login user id = %q, want %q", got, signupUserID)
	}

	// Use the access token from login to call an authenticated RPC.
	authed := h.AuthedClient(login.Msg.AccessToken)
	cur, err := authed.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if got := cur.Msg.GetUser().GetEmail(); got != email {
		t.Fatalf("GetCurrentUser email = %q, want %q", got, email)
	}
	if got := cur.Msg.GetUser().GetId(); got != signupUserID {
		t.Fatalf("GetCurrentUser id = %q, want %q", got, signupUserID)
	}
}

// TestPassword_GetCurrentUserUnauthenticated checks that hitting
// GetCurrentUser without a Bearer token returns Unauthenticated. The
// AuthMiddleware exempts this path from token-required enforcement
// but the handler itself rejects an empty user-id header.
func TestPassword_GetCurrentUserUnauthenticated(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	_, err := h.Client.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if err == nil {
		t.Fatalf("GetCurrentUser without token: expected error, got nil")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", got)
	}
}

// TestPassword_SignupWeakPasswordRejected ensures the password-strength
// validator runs through the full RPC path and produces an
// InvalidArgument code rather than a 500 / generic error.
func TestPassword_SignupWeakPasswordRejected(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	_, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "weak@example.com",
		Password: "short",
	}))
	if err == nil {
		t.Fatalf("expected weak-password rejection, got nil")
	}
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
	}
}

// TestPassword_SignupDuplicateEmailRejected creates a user, then
// tries to sign up again with the same email. The second call must
// fail with AlreadyExists.
func TestPassword_SignupDuplicateEmailRejected(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	const email = "dup@example.com"
	if _, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: goodPassword,
	})); err != nil {
		t.Fatalf("first PasswordSignup: %v", err)
	}

	_, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err == nil {
		t.Fatalf("duplicate signup: expected error, got nil")
	}
	if got := connect.CodeOf(err); got != connect.CodeAlreadyExists {
		t.Fatalf("duplicate signup code = %v, want AlreadyExists (err=%v)", got, err)
	}
}

// TestPassword_LoginWrongPasswordRejected_AuditEmitted asserts the
// service rejects an incorrect password with Unauthenticated AND
// writes a login_failure audit event. The audit recorder confirms
// the event reached the audit pipeline.
func TestPassword_LoginWrongPasswordRejected_AuditEmitted(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	const email = "victim@example.com"
	if _, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: goodPassword,
	})); err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	failuresBefore := h.Audit.CountByEventType("login_failure")

	_, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    email,
		Password: "Wrong-Password!9",
	}))
	if err == nil {
		t.Fatalf("login with wrong password: expected error, got nil")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", got, err)
	}

	failuresAfter := h.Audit.CountByEventType("login_failure")
	if failuresAfter <= failuresBefore {
		t.Fatalf("expected login_failure audit event count to increase: before=%d after=%d",
			failuresBefore, failuresAfter)
	}
}

// TestPassword_LoginNonExistentEmail_NoEnumeration verifies that
// logging in with an email that was never registered fails with the
// same error code AND the same generic message a wrong-password
// attempt yields. Leaking "user not found" vs "wrong password" lets
// attackers enumerate valid emails.
func TestPassword_LoginNonExistentEmail_NoEnumeration(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	// Register one real user to compare error messages against.
	const realEmail = "real@example.com"
	if _, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    realEmail,
		Password: goodPassword,
	})); err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	// Wrong password against the real user.
	_, errWrongPw := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    realEmail,
		Password: "Wrong-Password!9",
	}))
	if errWrongPw == nil {
		t.Fatalf("wrong-password login: expected error")
	}

	// Non-existent email.
	_, errMissing := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "ghost@example.com",
		Password: goodPassword,
	}))
	if errMissing == nil {
		t.Fatalf("missing-user login: expected error")
	}

	if connect.CodeOf(errMissing) != connect.CodeUnauthenticated {
		t.Fatalf("missing-user code = %v, want Unauthenticated", connect.CodeOf(errMissing))
	}

	// Both messages should be the generic "invalid email or password" string,
	// with no leakage of "user not found" or "no such user".
	for _, e := range []error{errWrongPw, errMissing} {
		msg := strings.ToLower(e.Error())
		if strings.Contains(msg, "not found") || strings.Contains(msg, "no such user") || strings.Contains(msg, "does not exist") {
			t.Fatalf("error message leaks account existence: %q", e.Error())
		}
		if !strings.Contains(msg, "invalid email or password") {
			t.Fatalf("expected generic 'invalid email or password' message, got %q", e.Error())
		}
	}
}
