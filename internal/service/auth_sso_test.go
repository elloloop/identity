package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
)

// ssoTestService returns an AuthService with SSO enabled and a TTL long
// enough that nothing lapses mid-test.
func ssoTestService(t *testing.T, repo *fakeRepo) *AuthService {
	t.Helper()
	svc := newTestAuthService(t, repo)
	svc.cfg.SSOEnabled = true
	svc.cfg.SSOSessionTTLSeconds = 3600
	svc.cfg.SSOContinueMode = config.SSOContinueModeTap
	return svc
}

// signInHosted runs a full hosted round trip and returns the callback result,
// which carries the SSO cookie value when one was established.
func signInHosted(ctx context.Context, t *testing.T, svc *AuthService, email string) *HostedOAuthCallbackResult {
	t.Helper()
	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-1", "")
	require.NoError(t, err)
	cb, err := svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode(email, "SSO User", "", "google"),
		stateTokenFromAuthURL(t, begin.AuthorizationURL), "", "1.2.3.4", "test-agent",
		[]string{"csrf-1"})
	require.NoError(t, err)
	return cb
}

// A completed hosted sign-in establishes the SSO session; the value is opaque
// and only its hash is stored.
func TestSSO_CookieEstablishedOnSuccessfulSignIn(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)
	ctx := withProject("proj-1")

	cb := signInHosted(ctx, t, svc, "sso-user@example.com")
	require.NotEmpty(t, cb.SSOCookieValue, "a completed sign-in must establish an SSO session")

	// The raw value never reaches storage — only its digest does.
	stored, err := repo.FindSSOSessionByHash(ctx, sha256Hex(cb.SSOCookieValue))
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.NotEqual(t, cb.SSOCookieValue, stored.TokenHash)
	assert.Equal(t, LoginMethodOAuth, stored.LoginMethod,
		"the establishing login method must be recorded for later policy replay")
	assert.True(t, stored.Active(svc.nowMs()))
}

// Nothing is established when the deployment has not opted in.
func TestSSO_NoCookieWhenDisabled(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo) // SSO left off
	ctx := withProject("proj-1")

	cb := signInHosted(ctx, t, svc, "no-sso@example.com")
	assert.Empty(t, cb.SSOCookieValue)
}

// A failed exchange must leave no session behind: the cookie is a record that
// somebody authenticated, so an authentication that did not happen may not
// produce one.
func TestSSO_NoCookieOnFailedSignIn(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)
	ctx := withProject("proj-1")

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-1", "")
	require.NoError(t, err)

	// Wrong CSRF token: the callback is refused before any exchange.
	_, err = svc.CompleteHostedOAuth(ctx, "google", fakeOAuthCode("nobody@example.com", "N", "", "google"),
		stateTokenFromAuthURL(t, begin.AuthorizationURL), "", "1.2.3.4", "test-agent",
		[]string{"wrong-csrf"})
	require.Error(t, err)

	require.Empty(t, repo.ssoSessions, "a refused callback must establish no SSO session")
}

// The fast path mints a FRESH pair per product. This is the property the whole
// design exists to preserve: SSO shares an authentication, never a token pair.
func TestSSO_ContinueMintsFreshPairPerProduct(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)
	ctx := withProject("proj-1")

	cb := signInHosted(ctx, t, svc, "multi-product@example.com")
	require.NotEmpty(t, cb.SSOCookieValue)

	// The product that signed in redeems its code.
	first, err := svc.RedeemOAuthCode(ctx, cb.Code, "1.2.3.4", "test-agent")
	require.NoError(t, err)
	require.NotEmpty(t, first.RefreshToken)

	// A SECOND product asks, with no provider round trip.
	cont, err := svc.ContinueSSOSession(ctx, cb.SSOCookieValue, "https://other-app.test/cb", "1.2.3.4", "other-agent")
	require.NoError(t, err)
	require.NotEmpty(t, cont.Code)
	assert.Equal(t, "https://other-app.test/cb", cont.ReturnTo)
	assert.NotEqual(t, cb.Code, cont.Code, "each product gets its own single-use code")

	second, err := svc.RedeemOAuthCode(ctx, cont.Code, "1.2.3.4", "other-agent")
	require.NoError(t, err)

	// Same person, different credentials — the whole point.
	assert.Equal(t, first.User.ID, second.User.ID)
	assert.NotEqual(t, first.RefreshToken, second.RefreshToken,
		"products must never share a refresh token")
	// The access token is deliberately NOT asserted distinct: it is a
	// stateless JWT over the same claims, so two minted in the same second
	// are legitimately byte-identical. The refresh token is the session
	// credential, and that is what must never be shared.

	// And each pair rotates on its own lineage: rotating the second product's
	// token must not disturb the first product's.
	_, _, rotatedRefresh, err := svc.RefreshToken(ctx, second.RefreshToken, "1.2.3.4", "other-agent")
	require.NoError(t, err)
	assert.NotEqual(t, second.RefreshToken, rotatedRefresh, "refresh tokens rotate")

	_, _, stillValid, err := svc.RefreshToken(ctx, first.RefreshToken, "1.2.3.4", "test-agent")
	require.NoError(t, err, "one product's rotation must not invalidate another's session")
	assert.NotEmpty(t, stillValid)
}

// A continue rolls the session's expiry forward.
func TestSSO_ContinueRollsTheWindow(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)
	ctx := withProject("proj-1")

	cb := signInHosted(ctx, t, svc, "rolling@example.com")
	hash := sha256Hex(cb.SSOCookieValue)

	before, err := repo.FindSSOSessionByHash(ctx, hash)
	require.NoError(t, err)
	// Wind the stored expiry back so a roll is observable.
	require.NoError(t, repo.TouchSSOSession(ctx, hash, before.LastUsedAtMs, svc.nowMs()+1000))

	_, err = svc.ContinueSSOSession(ctx, cb.SSOCookieValue, "https://app.test/finish", "1.2.3.4", "agent")
	require.NoError(t, err)

	after, err := repo.FindSSOSessionByHash(ctx, hash)
	require.NoError(t, err)
	assert.Greater(t, after.ExpiresAtMs, svc.nowMs()+1000, "a successful continue re-anchors the rolling expiry")
}

// Expired, revoked, unknown and absent cookies all fall back identically —
// the caller takes the normal sign-in flow, and the endpoint is no oracle.
func TestSSO_InactiveSessionsFallBackCleanly(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)
	ctx := withProject("proj-1")

	t.Run("expired", func(t *testing.T) {
		cb := signInHosted(ctx, t, svc, "expired@example.com")
		hash := sha256Hex(cb.SSOCookieValue)
		require.NoError(t, repo.TouchSSOSession(ctx, hash, 1, svc.nowMs()-1))

		_, err := svc.ContinueSSOSession(ctx, cb.SSOCookieValue, "https://app.test/finish", "ip", "ua")
		assert.True(t, errors.Is(err, ErrSSOSessionInvalid), "got %v", err)
	})

	t.Run("revoked", func(t *testing.T) {
		cb := signInHosted(ctx, t, svc, "revoked@example.com")
		require.NoError(t, svc.EndSSOSession(ctx, cb.SSOCookieValue))

		_, err := svc.ContinueSSOSession(ctx, cb.SSOCookieValue, "https://app.test/finish", "ip", "ua")
		assert.True(t, errors.Is(err, ErrSSOSessionInvalid), "got %v", err)
	})

	t.Run("unknown", func(t *testing.T) {
		_, err := svc.ContinueSSOSession(ctx, "not-a-real-cookie", "https://app.test/finish", "ip", "ua")
		assert.True(t, errors.Is(err, ErrSSOSessionInvalid), "got %v", err)
	})

	t.Run("absent", func(t *testing.T) {
		_, err := svc.ContinueSSOSession(ctx, "", "https://app.test/finish", "ip", "ua")
		assert.True(t, errors.Is(err, ErrSSOSessionInvalid), "got %v", err)
	})

	t.Run("disabled deployment", func(t *testing.T) {
		offRepo := newFakeRepo()
		offSvc := ssoTestService(t, offRepo)
		offCtx := withProject("proj-1")
		cb := signInHosted(offCtx, t, offSvc, "later-disabled@example.com")

		offSvc.cfg.SSOEnabled = false
		_, err := offSvc.ContinueSSOSession(offCtx, cb.SSOCookieValue, "https://app.test/finish", "ip", "ua")
		assert.True(t, errors.Is(err, ErrSSOSessionInvalid), "got %v", err)
	})
}

// Authentication is not authorization: a project whose access mode no longer
// admits the account refuses the fast path, exactly as a cold sign-in would.
func TestSSO_ContinueEnforcesProjectAccess(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)

	openCtx := withProject("proj-1")
	cb := signInHosted(openCtx, t, svc, "listed@example.com")
	require.NotEmpty(t, cb.SSOCookieValue)

	// The same deployment, now an allowlist project that does not list them.
	allowlistCtx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "proj-1",
		Access: ProjectAccessConfig{
			Mode:          AccessModeAllowlist,
			AllowedEmails: []string{"someone-else@example.com"},
		},
	})

	_, err := svc.ContinueSSOSession(allowlistCtx, cb.SSOCookieValue, "https://app.test/finish", "ip", "ua")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccessNotAllowed),
		"an off-allowlist account must be refused on the fast path: got %v", err)

	// A closed project refuses too.
	closedCtx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "proj-1",
		Access:    ProjectAccessConfig{Mode: AccessModeClosed},
	})
	_, err = svc.ContinueSSOSession(closedCtx, cb.SSOCookieValue, "https://app.test/finish", "ip", "ua")
	assert.True(t, errors.Is(err, ErrAccessNotAllowed), "got %v", err)
}

// A deactivated account cannot spend a session it established while active.
func TestSSO_ContinueEnforcesAccountStatus(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)
	ctx := withProject("proj-1")

	cb := signInHosted(ctx, t, svc, "deactivated@example.com")
	user, err := repo.FindUserByEmail(ctx, "deactivated@example.com")
	require.NoError(t, err)
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"status": "deactivated"}))

	_, err = svc.ContinueSSOSession(ctx, cb.SSOCookieValue, "https://app.test/finish", "ip", "ua")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSSOSessionInvalid),
		"a real denial must not be reported as a missing session")
}

// An account owing a second factor gets no fast path — the cookie is not a
// stand-in for the factor.
func TestSSO_ContinueRefusesWhenSecondFactorRequired(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)
	ctx := withProject("proj-1")

	cb := signInHosted(ctx, t, svc, "totp@example.com")
	user, err := repo.FindUserByEmail(ctx, "totp@example.com")
	require.NoError(t, err)
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"totp_required": true}))

	_, err = svc.ContinueSSOSession(ctx, cb.SSOCookieValue, "https://app.test/finish", "ip", "ua")
	assert.True(t, errors.Is(err, ErrSSOSecondFactorRequired), "got %v", err)
}

// A login policy that no longer permits the ESTABLISHING method refuses the
// fast path: the cookie must not launder a login the tenant has since barred.
func TestSSO_ContinueReplaysPolicyAgainstEstablishingMethod(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)

	svc.WithLoginGovernance(claimedPasswordOnlyGovernance())

	openCtx := withProject("proj-1")
	cb := signInHosted(openCtx, t, svc, "policy@example.com")

	// The project now allows password logins only. The session was established
	// by oauth, so replaying the ORIGINAL method is what makes this a refusal;
	// a synthetic "sso" method would have sailed through.
	policyCtx := withProjectLoginDefaults("proj-1", LoginMethodPassword, false)
	_, err := svc.ContinueSSOSession(policyCtx, cb.SSOCookieValue, "https://app.test/finish", "ip", "ua")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSSOSessionInvalid),
		"a policy refusal must be a denial, not a missing session: got %v", err)
}

// return_to is required; the HTTP layer allowlists it before we get here.
func TestSSO_ContinueRequiresReturnTo(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)
	ctx := withProject("proj-1")

	cb := signInHosted(ctx, t, svc, "no-return@example.com")
	_, err := svc.ContinueSSOSession(ctx, cb.SSOCookieValue, "   ", "ip", "ua")
	assert.True(t, errors.Is(err, ErrInvalidArgument), "got %v", err)
}

// Introspection names the account and the deployment's continue mode, and
// says nothing at all when there is no usable session.
func TestSSO_Introspect(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)
	ctx := withProject("proj-1")

	cb := signInHosted(ctx, t, svc, "introspect@example.com")

	view, err := svc.IntrospectSSOSession(ctx, cb.SSOCookieValue)
	require.NoError(t, err)
	assert.Equal(t, "introspect@example.com", view.Email)
	assert.Equal(t, config.SSOContinueModeTap, view.ContinueMode)

	svc.cfg.SSOContinueMode = config.SSOContinueModeSilent
	view, err = svc.IntrospectSSOSession(ctx, cb.SSOCookieValue)
	require.NoError(t, err)
	assert.Equal(t, config.SSOContinueModeSilent, view.ContinueMode)

	require.NoError(t, svc.EndSSOSession(ctx, cb.SSOCookieValue))
	_, err = svc.IntrospectSSOSession(ctx, cb.SSOCookieValue)
	assert.True(t, errors.Is(err, ErrSSOSessionInvalid), "got %v", err)
}

// The session outlives a per-product logout. That is the approved model:
// signing out of one app is not signing out of the account.
func TestSSO_SurvivesPerProductLogout(t *testing.T) {
	repo := newFakeRepo()
	svc := ssoTestService(t, repo)
	ctx := withProject("proj-1")

	cb := signInHosted(ctx, t, svc, "logout-one@example.com")
	login, err := svc.RedeemOAuthCode(ctx, cb.Code, "1.2.3.4", "agent")
	require.NoError(t, err)

	require.NoError(t, svc.Logout(ctx, login.RefreshToken))

	// That product's refresh token is dead...
	_, _, _, err = svc.RefreshToken(ctx, login.RefreshToken, "1.2.3.4", "agent")
	require.Error(t, err)

	// ...but the browser is still signed in for the next product.
	cont, err := svc.ContinueSSOSession(ctx, cb.SSOCookieValue, "https://other.test/cb", "1.2.3.4", "agent")
	require.NoError(t, err)
	assert.NotEmpty(t, cont.Code)
}
