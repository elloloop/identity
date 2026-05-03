//go:build integration

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
)

// signupViaClient is a small helper that produces a fresh user and
// returns the initial token pair. Used as the precondition for the
// session-flow tests below.
func signupViaClient(t *testing.T, h *Harness, email string) (accessToken, refreshToken, userID string) {
	t.Helper()
	resp, err := h.Client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup(%s): %v", email, err)
	}
	return resp.Msg.AccessToken, resp.Msg.RefreshToken, resp.Msg.GetUser().GetId()
}

// TestSession_RefreshRoundTrip verifies that a refresh token issued
// at signup can be exchanged for a fresh access+refresh pair, and the
// new access token works with GetCurrentUser.
func TestSession_RefreshRoundTrip(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	_, refresh, userID := signupViaClient(t, h, "refresh@example.com")

	resp, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: refresh,
	}))
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if resp.Msg.AccessToken == "" {
		t.Fatalf("refresh returned empty access token")
	}
	if resp.Msg.RefreshToken == "" {
		t.Fatalf("refresh returned empty refresh token")
	}
	if got := resp.Msg.GetUser().GetId(); got != userID {
		t.Fatalf("user id = %q, want %q", got, userID)
	}

	// New access token must be usable.
	authed := h.AuthedClient(resp.Msg.AccessToken)
	if _, err := authed.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{})); err != nil {
		t.Fatalf("GetCurrentUser with refreshed access token: %v", err)
	}
}

// TestSession_RefreshTokenRotation verifies the security-critical
// invariant: once a refresh token has been used, it MUST be rejected
// on subsequent attempts. This catches stolen-cookie replay attacks.
func TestSession_RefreshTokenRotation(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	_, oldRefresh, _ := signupViaClient(t, h, "rotate@example.com")

	// First refresh succeeds and returns a new refresh token.
	resp, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: oldRefresh,
	}))
	if err != nil {
		t.Fatalf("first RefreshToken: %v", err)
	}
	if resp.Msg.RefreshToken == oldRefresh {
		t.Fatalf("expected a NEW refresh token after rotation; got the same token back")
	}

	// Second attempt with the OLD token must fail.
	_, err = h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: oldRefresh,
	}))
	if err == nil {
		t.Fatalf("expected old refresh token to be invalid after rotation")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("rotated-token code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

// TestSession_MultipleSessionsPerUser verifies that two independent
// PasswordLogin calls (e.g. from a phone and a laptop, with different
// IPs and User-Agents) yield two coexisting refresh tokens for the
// same user. Logging out of one must not affect the other.
func TestSession_MultipleSessionsPerUser(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	const email = "multi@example.com"
	_, _, userID := signupViaClient(t, h, email)

	loginFrom := func(ip, ua string) string {
		req := connect.NewRequest(&identitypb.PasswordLoginRequest{
			Email:    email,
			Password: goodPassword,
		})
		req.Header().Set("X-Forwarded-For", ip)
		req.Header().Set("User-Agent", ua)
		resp, err := h.Client.PasswordLogin(ctx, req)
		if err != nil {
			t.Fatalf("PasswordLogin(%s): %v", ua, err)
		}
		return resp.Msg.RefreshToken
	}

	deviceA := loginFrom("10.0.0.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) Chrome/120.0")
	deviceB := loginFrom("10.0.0.2", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1")

	if deviceA == deviceB {
		t.Fatalf("two logins returned identical refresh tokens")
	}

	// Includes the signup-issued session => 3 active sessions total.
	if got := h.Repo.CountRefreshTokensForUser(userID); got != 3 {
		t.Fatalf("active sessions = %d, want 3", got)
	}

	// Refresh device A; device B's token must still work afterwards.
	if _, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: deviceA,
	})); err != nil {
		t.Fatalf("refresh device A: %v", err)
	}

	if _, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: deviceB,
	})); err != nil {
		t.Fatalf("refresh device B (independent session) failed: %v", err)
	}
}

// TestSession_LogoutInvalidatesSession ensures Logout deletes the
// refresh token, so a later refresh with the same token fails.
func TestSession_LogoutInvalidatesSession(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	_, refresh, _ := signupViaClient(t, h, "logout@example.com")

	if _, err := h.Client.Logout(ctx, connect.NewRequest(&identitypb.LogoutRequest{
		RefreshToken: refresh,
	})); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	_, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: refresh,
	}))
	if err == nil {
		t.Fatalf("expected refresh after logout to fail")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("post-logout refresh code = %v, want Unauthenticated", got)
	}
}
