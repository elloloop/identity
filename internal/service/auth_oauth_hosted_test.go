package service

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stateTokenFromAuthURL pulls the `state` query parameter (the signed
// hosted state token) out of the authorization URL the stub authorizer
// produced.
func stateTokenFromAuthURL(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	st := u.Query().Get("state")
	require.NotEmpty(t, st, "auth URL carried no state token")
	return st
}

func TestHostedOAuth_BeginCompleteRedeem(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123")
	require.NoError(t, err)
	require.NotEmpty(t, begin.AuthorizationURL)
	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)

	cb, err := svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode("hosted@example.com", "Hosted", "", "google"),
		stateToken, "", "1.2.3.4", "test-agent", []string{"csrf-123"})
	require.NoError(t, err)
	assert.Equal(t, "https://app.test/finish", cb.ReturnTo)
	require.NotEmpty(t, cb.Code)

	redeemed, err := svc.RedeemOAuthCode(ctx, cb.Code, "1.2.3.4", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, redeemed.User)
	assert.Equal(t, "hosted@example.com", redeemed.User.Email)
	assert.NotEmpty(t, redeemed.AccessToken)
	assert.NotEmpty(t, redeemed.RefreshToken)

	// Single-use: a replay is rejected.
	_, err = svc.RedeemOAuthCode(ctx, cb.Code, "1.2.3.4", "test-agent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOAuthCodeInvalid))
}

func TestHostedOAuth_Begin_InputErrors(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()

	_, err := svc.BeginHostedOAuth(ctx, "", "https://identity.test/cb", "https://app.test/", "csrf-123")
	assert.True(t, errors.Is(err, ErrInvalidArgument))

	_, err = svc.BeginHostedOAuth(ctx, "google", "", "https://app.test/", "csrf-123")
	assert.True(t, errors.Is(err, ErrInvalidArgument))

	_, err = svc.BeginHostedOAuth(ctx, "google", "https://identity.test/cb", "", "csrf-123")
	assert.True(t, errors.Is(err, ErrInvalidArgument))

	_, err = svc.BeginHostedOAuth(ctx, "unknown", "https://identity.test/cb", "https://app.test/", "csrf-123")
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestHostedOAuth_Begin_DisabledNoRegistry(t *testing.T) {
	svc := newTestAuthServiceNoOAuth(t, newFakeRepo())
	_, err := svc.BeginHostedOAuth(context.Background(), "google",
		"https://identity.test/cb", "https://app.test/", "csrf-123")
	assert.True(t, errors.Is(err, ErrOAuthDisabled))
}

func TestHostedOAuth_Complete_TamperedStateRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123")
	require.NoError(t, err)
	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)

	// Flip a character in the signature — verification must fail.
	tampered := stateToken[:len(stateToken)-2] + "AA"
	_, err = svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode("hosted@example.com", "Hosted", "", "google"),
		tampered, "", "", "", []string{"csrf-123"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestHostedOAuth_Complete_CSRFMismatchRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123")
	require.NoError(t, err)
	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)

	_, err = svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode("hosted@example.com", "Hosted", "", "google"),
		stateToken, "", "", "", []string{"wrong-csrf-token"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestHostedOAuth_Complete_ProviderMismatchRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123")
	require.NoError(t, err)
	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)

	// The token was minted for google but the callback path says github.
	_, err = svc.CompleteHostedOAuth(ctx, "github",
		fakeOAuthCode("hosted@example.com", "Hosted", "", "google"),
		stateToken, "", "", "", []string{"csrf-123"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestRedeemOAuthCode_DisabledNoRegistry(t *testing.T) {
	svc := newTestAuthServiceNoOAuth(t, newFakeRepo())
	_, err := svc.RedeemOAuthCode(context.Background(), "any-code", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOAuthDisabled))
}

func TestRedeemOAuthCode_UnknownCode(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())
	_, err := svc.RedeemOAuthCode(context.Background(), "nonexistent", "", "")
	assert.True(t, errors.Is(err, ErrOAuthCodeInvalid))
}

func TestRedeemOAuthCode_EmptyCode(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())
	_, err := svc.RedeemOAuthCode(context.Background(), "", "", "")
	assert.True(t, errors.Is(err, ErrOAuthCodeInvalid))
}
