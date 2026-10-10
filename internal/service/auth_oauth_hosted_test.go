package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/passkeys"
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
	ctx := withProject("proj-1")

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "")
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
	ctx := withProject("proj-1")

	_, err := svc.BeginHostedOAuth(ctx, "", "https://identity.test/cb", "https://app.test/", "csrf-123", "")
	assert.True(t, errors.Is(err, ErrInvalidArgument))

	_, err = svc.BeginHostedOAuth(ctx, "google", "", "https://app.test/", "csrf-123", "")
	assert.True(t, errors.Is(err, ErrInvalidArgument))

	_, err = svc.BeginHostedOAuth(ctx, "google", "https://identity.test/cb", "", "csrf-123", "")
	assert.True(t, errors.Is(err, ErrInvalidArgument))

	_, err = svc.BeginHostedOAuth(ctx, "google", "https://identity.test/cb", "https://app.test/", "", "")
	assert.True(t, errors.Is(err, ErrInvalidArgument))

	_, err = svc.BeginHostedOAuth(ctx, "unknown", "https://identity.test/cb", "https://app.test/", "csrf-123", "")
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

// BeginHostedOAuth requires a resolved project scope: the signed state token
// binds the flow to a project, so an unscoped request cannot start one.
func TestHostedOAuth_Begin_MissingScopeRejected(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())

	_, err := svc.BeginHostedOAuth(context.Background(), "google",
		"https://identity.test/cb", "https://app.test/", "csrf-123", "")
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestHostedOAuth_Begin_DisabledNoRegistry(t *testing.T) {
	svc := newTestAuthServiceNoOAuth(t, newFakeRepo())
	_, err := svc.BeginHostedOAuth(withProject("proj-1"), "google",
		"https://identity.test/cb", "https://app.test/", "csrf-123", "")
	assert.True(t, errors.Is(err, ErrOAuthDisabled))
}

func TestHostedOAuth_Complete_TamperedStateRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := withProject("proj-1")

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "")
	require.NoError(t, err)
	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)

	// Flip the penultimate signature character to a guaranteed-different value —
	// verification must fail. (Overwriting the tail with a fixed literal was a
	// no-op when the token already ended in it; the penultimate base64url char
	// is always significant, unlike the final one which can carry padding bits.)
	tb := []byte(stateToken)
	i := len(tb) - 2
	if tb[i] == 'A' {
		tb[i] = 'B'
	} else {
		tb[i] = 'A'
	}
	tampered := string(tb)
	_, err = svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode("hosted@example.com", "Hosted", "", "google"),
		tampered, "", "", "", []string{"csrf-123"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

func TestHostedOAuth_Complete_CSRFMismatchRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := withProject("proj-1")

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "")
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
	ctx := withProject("proj-1")

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "")
	require.NoError(t, err)
	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)

	// The token was minted for google but the callback path says github.
	_, err = svc.CompleteHostedOAuth(ctx, "github",
		fakeOAuthCode("hosted@example.com", "Hosted", "", "google"),
		stateToken, "", "", "", []string{"csrf-123"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
}

// A project key prefixes the OAuth state and survives the round trip —
// including a key that itself contains the separator character.
func TestHostedOAuth_WithProjectKeyPrefix(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := withProject("proj-1")

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "proj:with:colon")
	require.NoError(t, err)

	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)
	require.True(t, strings.HasPrefix(stateToken, "proj:with:colon:"), "state %q must carry the project-key prefix", stateToken)

	cb, err := svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode("hosted@example.com", "Hosted", "", "google"),
		stateToken, "", "1.2.3.4", "test-agent", []string{"csrf-123"})
	require.NoError(t, err)
	require.NotEmpty(t, cb.Code)
}

// A state token minted for one project cannot complete a login in another:
// the signed project_id claim must match the callback request's scope.
func TestHostedOAuth_Complete_ProjectMismatchRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	begin, err := svc.BeginHostedOAuth(withProject("proj-1"), "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "proj-1")
	require.NoError(t, err)
	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)

	_, err = svc.CompleteHostedOAuth(withProject("proj-2"), "google",
		fakeOAuthCode("hosted@example.com", "Hosted", "", "google"),
		stateToken, "", "1.2.3.4", "test-agent", []string{"csrf-123"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated))
	assert.Contains(t, err.Error(), "project mismatch")
}

// hubSharingService builds a service whose default project is "default" so
// every other project id is genuinely non-default (unlike testConfig, whose
// empty DefaultProjectID makes every request resolve as the default project),
// with the env registry as the hub's providers and hub sharing set to sharing.
func hubSharingService(t *testing.T, repo *fakeRepo, sharing bool) *AuthService {
	t.Helper()
	cfg := testConfig()
	cfg.DefaultProjectID = "default"
	cfg.OAuthHubSharing = sharing
	passkeysSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin,
	})
	return NewAuthServiceWithOAuth(
		repo, cfg, testKeyRing(t), passkeysSvc,
		audit.NewLogger(nil, "test", nil),
		testTotpKey(), testTotpRecoveryPepper(), email.NewLogOnly(zap.NewNop()), nil, zap.NewNop(),
		defaultTestOAuthRegistry(),
	)
}

// The central-hub regression: a NON-DEFAULT project with no providers of its
// own completes the whole hosted flow — begin, callback, redeem — by
// borrowing the hub's provider when GATEWAY_OAUTH_HUB_SHARING is on.
func TestHostedOAuth_HubSharing_NonDefaultProjectFullFlow(t *testing.T) {
	repo := newFakeRepo()
	svc := hubSharingService(t, repo, true)
	ctx := withProject("proj-hub")

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://hub.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "pk_hub")
	require.NoError(t, err, "begin must borrow the hub provider for a zero-config project")
	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)
	require.True(t, strings.HasPrefix(stateToken, "pk_hub:"))

	cb, err := svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode("hub-user@example.com", "Hub User", "", "google"),
		stateToken, "", "1.2.3.4", "test-agent", []string{"csrf-123"})
	require.NoError(t, err, "callback must borrow the hub provider for a zero-config project")
	require.NotEmpty(t, cb.Code)

	login, err := svc.RedeemOAuthCode(ctx, cb.Code, "1.2.3.4", "test-agent")
	require.NoError(t, err, "redeem must not report OAuth disabled for a hub-shared project")
	assert.Equal(t, "hub-user@example.com", login.User.Email)
}

// With hub sharing off (the default), the strict ADR-0010 isolation holds: a
// non-default project without its own providers cannot use the hosted flow.
func TestHostedOAuth_HubSharingOff_NonDefaultProjectDisabled(t *testing.T) {
	repo := newFakeRepo()
	svc := hubSharingService(t, repo, false)

	_, err := svc.BeginHostedOAuth(withProject("proj-hub"), "google",
		"https://hub.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "pk_hub")
	assert.True(t, errors.Is(err, ErrOAuthDisabled))
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

// A sign-in refused after the state token verified names the refusal for the
// app at the verified return_to; a refusal over an account the provider did
// not prove reads like any failed exchange.
func TestHostedOAuth_Complete_RefusalCarriesErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		seed  func(t *testing.T, repo *fakeRepo)
		code  string
		want  string
		cause error
	}{
		{
			name: "unverified address",
			seed: func(t *testing.T, repo *fakeRepo) {
				t.Helper()
				user := seedUser(repo, "unproven@example.com", "", StatusActive)
				require.NoError(t, repo.CreateOAuthIdentity(context.Background(), &OAuthIdentity{
					UserID: user.ID, Provider: "google", ProviderUserID: "sub-linker@example.com", CreatedAt: 1,
				}))
			},
			code:  fakeOAuthCode("linker@example.com", "Linker", "", "google"),
			want:  HostedOAuthErrorEmailNotVerified,
			cause: ErrEmailVerificationRequired,
		},
		{
			name: "deactivated account",
			seed: func(_ *testing.T, repo *fakeRepo) {
				seedUser(repo, "gone@example.com", "", StatusDeactivated).EmailVerified = true
			},
			code:  fakeOAuthCode("gone@example.com", "Gone", "", "google"),
			want:  HostedOAuthErrorAccountDisabled,
			cause: ErrAccountNotActive,
		},
		{
			name: "locked account",
			seed: func(_ *testing.T, repo *fakeRepo) {
				u := seedUser(repo, "locked@example.com", "", StatusActive)
				u.EmailVerified = true
				u.LockedUntil = time.Now().Add(time.Hour).UnixMilli()
			},
			code:  fakeOAuthCode("locked@example.com", "Locked", "", "google"),
			want:  HostedOAuthErrorAccountLocked,
			cause: ErrAccountLocked,
		},
		{
			name:  "provider did not verify its address",
			code:  "unverified|someone@example.com",
			want:  HostedOAuthErrorAccessDenied,
			cause: ErrUnauthenticated,
		},
		{
			name:  "failed exchange",
			code:  "err|bad-code",
			want:  HostedOAuthErrorAccessDenied,
			cause: ErrUnauthenticated,
		},
		{
			name: "another account the provider address does not prove",
			seed: func(_ *testing.T, repo *fakeRepo) {
				u := seedUser(repo, "owner@example.com", "", StatusDeactivated)
				u.EmailVerified = false
			},
			code:  fakeOAuthCode("owner+tag@example.com", "Tagged", "", "google"),
			want:  HostedOAuthErrorAccessDenied,
			cause: ErrUnauthenticated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			svc.cfg.AuthRequireVerifiedEmail = true
			if tc.seed != nil {
				tc.seed(t, repo)
			}
			ctx := withProject("proj-1")

			begin, err := svc.BeginHostedOAuth(ctx, "google",
				"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "")
			require.NoError(t, err)

			_, err = svc.CompleteHostedOAuth(ctx, "google", tc.code,
				stateTokenFromAuthURL(t, begin.AuthorizationURL), "", "1.2.3.4", "test-agent", []string{"csrf-123"})
			var refusal *HostedOAuthRefusalError
			require.ErrorAs(t, err, &refusal)
			assert.Equal(t, tc.want, refusal.Code)
			assert.Equal(t, "https://app.test/finish", refusal.ReturnTo)
			assert.Equal(t, "csrf-123", refusal.CSRFToken)
			assert.ErrorIs(t, err, tc.cause)
		})
	}
}

// A failure before the state token verified has no trusted return_to, so it
// is never a refusal the callback could redirect with.
func TestHostedOAuth_Complete_UnverifiedStateIsNoRefusal(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())
	_, err := svc.CompleteHostedOAuth(withProject("proj-1"), "google",
		fakeOAuthCode("hosted@example.com", "Hosted", "", "google"),
		"not-a-state-token", "", "", "", []string{"csrf-123"})
	var refusal *HostedOAuthRefusalError
	assert.False(t, errors.As(err, &refusal))
	assert.ErrorIs(t, err, ErrUnauthenticated)
}

func TestHostedOAuthErrorCode_UnexpectedFailureIsServerError(t *testing.T) {
	assert.Equal(t, HostedOAuthErrorServer, hostedOAuthErrorCode(errors.New("database unavailable")))
	assert.Equal(t, HostedOAuthErrorUnavailable, hostedOAuthErrorCode(ErrOAuthDisabled))
	assert.Equal(t, HostedOAuthErrorUnavailable, hostedOAuthErrorCode(fmt.Errorf("%w: sweep", ErrUnavailable)))
	assert.Equal(t, HostedOAuthErrorUnavailable, hostedOAuthErrorCode(ErrAssuranceUnavailable))
}
