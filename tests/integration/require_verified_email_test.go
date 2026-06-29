//go:build integration

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
)

// TestRequireVerifiedEmail_BlocksThenAllows exercises the
// GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL gate end-to-end through the Connect
// stack. With the flag on (the production default), an unverified password
// account must not get a live session at signup and must not be able to log
// in; once the email is verified, login succeeds. This guards the account
// pre-hijacking fix at the wire level — the service unit tests cover the logic,
// but the harness defaults the flag off, so without this the default-on
// behavior is never exercised through a real handler.
func TestRequireVerifiedEmail_BlocksThenAllows(t *testing.T) {
	t.Parallel()
	h := StartServer(t, WithConfig(func(c *config.Config) {
		c.AuthRequireVerifiedEmail = true
	}))
	ctx := context.Background()

	const email = "verify-gate@example.com"

	// Signup must NOT auto-login an unverified account: tokens are blank.
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    email,
		Password: goodPassword,
	}))
	require.NoError(t, err, "signup itself still succeeds (account is created)")
	require.Empty(t, signup.Msg.GetAccessToken(), "unverified signup must not return a live session")
	require.Empty(t, signup.Msg.GetRefreshToken(), "unverified signup must not return a refresh token")
	userID := signup.Msg.GetUser().GetId()
	require.NotEmpty(t, userID, "the account is still created so the client can prompt verification")

	// Login is blocked with FailedPrecondition while the email is unverified —
	// even though the password is correct (so this is not an auth/enumeration
	// signal, it is a "do something else first" signal).
	_, err = h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    email,
		Password: goodPassword,
	}))
	require.Error(t, err, "unverified login must be rejected")
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err),
		"unverified login must map to FailedPrecondition, got: %v", err)

	// Verify the email, then the same login succeeds and returns a session.
	mem, ok := h.Repo.(*MemRepo)
	if !ok {
		t.Skip("verify-release leg uses the memory backend's direct verify helper")
	}
	require.NoError(t, mem.SetUserEmailVerified(ctx, userID, 1))

	login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    email,
		Password: goodPassword,
	}))
	require.NoError(t, err, "login must succeed once the email is verified")
	require.NotEmpty(t, login.Msg.GetAccessToken(), "verified login returns a session")
	require.Equal(t, userID, login.Msg.GetUser().GetId(), "same account, not a duplicate")
}

// TestRequireVerifiedEmail_SignupResponseIndistinguishable guards the
// account-enumeration property: with the gate on, signing up a brand-new email
// and signing up an ALREADY-registered email must produce the same observable
// response. A new signup returns no session (verification required); the
// duplicate-signup decoy must therefore also return no session, otherwise
// empty-vs-non-empty tokens would leak whether the address is registered.
func TestRequireVerifiedEmail_SignupResponseIndistinguishable(t *testing.T) {
	t.Parallel()
	h := StartServer(t, WithConfig(func(c *config.Config) {
		c.AuthRequireVerifiedEmail = true
	}))
	ctx := context.Background()

	const existing = "already-registered@example.com"

	// Seed an existing account.
	_, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    existing,
		Password: goodPassword,
	}))
	require.NoError(t, err)

	// New email signup.
	newResp, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "brand-new@example.com",
		Password: goodPassword,
	}))
	require.NoError(t, err)

	// Duplicate signup for the already-registered email.
	dupResp, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    existing,
		Password: goodPassword,
	}))
	require.NoError(t, err)

	// Both must be session-less: a registered and an unregistered email are
	// indistinguishable from the response.
	require.Empty(t, newResp.Msg.GetAccessToken(), "new signup must not return a session under the gate")
	require.Empty(t, dupResp.Msg.GetAccessToken(), "duplicate signup must not return a session under the gate")
	require.Equal(t, newResp.Msg.GetAccessToken() == "", dupResp.Msg.GetAccessToken() == "",
		"new and duplicate signup must be indistinguishable by token presence")
	require.Equal(t, newResp.Msg.GetRefreshToken() == "", dupResp.Msg.GetRefreshToken() == "",
		"new and duplicate signup must be indistinguishable by refresh-token presence")
}
