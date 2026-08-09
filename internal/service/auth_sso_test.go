package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

const (
	ssoTestReturnTo  = "https://product-a.example.com/callback"
	ssoTestAllowlist = "https://product-a.example.com/"
)

// newSSOTestService builds an SSO-enabled AuthService over a fresh fakeRepo
// with the return allowlist pointing at the product-a fixture origin.
func newSSOTestService(t *testing.T) (*AuthService, *fakeRepo) {
	t.Helper()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.SSOEnabled = true
	svc.cfg.SSOSessionTTLSeconds = 3600
	svc.returnAllow = ParseReturnAllowlist(ssoTestAllowlist)
	return svc, repo
}

// ssoScope returns a context carrying an open-access project scope, as the
// project-resolution middleware would inject it.
func ssoScope(projectID string) context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: projectID,
		Access:    ProjectAccessConfig{Mode: AccessModeOpen},
	})
}

// mintSSO mints a real SSO session via the service so the test's cookie
// token matches what production stores (hash of the plaintext).
func mintSSO(t *testing.T, svc *AuthService, ctx context.Context, userID string) string {
	t.Helper()
	raw, err := svc.mintSSOSession(ctx, userID, LoginMethodOAuth)
	require.NoError(t, err)
	return raw
}

func ssoSessionAlive(t *testing.T, svc *AuthService, ctx context.Context, raw string) bool {
	t.Helper()
	rec, err := svc.repo(ctx).GetSSOSessionByHash(ctx, sha256Hex(raw))
	require.NoError(t, err)
	return rec != nil
}

func TestContinueWithSSO_HappyPathMintsRedeemableCode(t *testing.T) {
	svc, repo := newSSOTestService(t)
	user := seedUser(repo, "alice@example.com", "", "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	res, err := svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.Equal(t, ssoTestReturnTo, res.ReturnTo)
	require.NotEmpty(t, res.Code)

	// The code redeems into a fresh token pair for THIS product via the
	// existing single-use redeem — rotation semantics inherited.
	login, err := svc.RedeemOAuthCode(ctx, res.Code, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.Equal(t, user.ID, login.User.ID)
	require.NotEmpty(t, login.AccessToken)
	require.NotEmpty(t, login.RefreshToken)

	// Single-use: a replay of the same code is rejected.
	_, err = svc.RedeemOAuthCode(ctx, res.Code, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrOAuthCodeInvalid)

	// The SSO session itself is NOT consumed: a second product can
	// continue-as with the same cookie and gets its OWN code.
	res2, err := svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotEqual(t, res.Code, res2.Code)
}

func TestContinueWithSSO_DisabledByDefault(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo) // SSO not enabled
	svc.returnAllow = ParseReturnAllowlist(ssoTestAllowlist)
	user := seedUser(repo, "alice@example.com", "", "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	_, err := svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrSSODisabled)
}

func TestRedeemOAuthCode_SSOOnlyDeployment(t *testing.T) {
	// No OAuth provider configured at all: redeem must still work because
	// SSO continue-as mints the codes.
	repo := newFakeRepo()
	svc := newTestAuthServiceNoOAuth(t, repo)
	svc.cfg.SSOEnabled = true
	svc.cfg.SSOSessionTTLSeconds = 3600
	svc.returnAllow = ParseReturnAllowlist(ssoTestAllowlist)
	user := seedUser(repo, "alice@example.com", "", "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	res, err := svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.NoError(t, err)
	login, err := svc.RedeemOAuthCode(ctx, res.Code, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.Equal(t, user.ID, login.User.ID)
}

func TestContinueWithSSO_RejectsUnknownAndExpiredSessions(t *testing.T) {
	now := time.UnixMilli(1_000_000_000_000)
	repo := newFakeRepo()
	svc := newTestAuthServiceWithTime(t, repo, func() time.Time { return now })
	svc.cfg.SSOEnabled = true
	svc.cfg.SSOSessionTTLSeconds = 60
	svc.returnAllow = ParseReturnAllowlist(ssoTestAllowlist)
	user := seedUser(repo, "alice@example.com", "", "active")
	ctx := ssoScope("project-a")

	// An attacker-guessed cookie value names no session.
	_, err := svc.ContinueWithSSO(ctx, "forged-cookie-value", ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrSSOSessionInvalid)

	// A real but expired session is rejected identically.
	raw := mintSSO(t, svc, ctx, user.ID)
	now = now.Add(2 * time.Minute)
	_, err = svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrSSOSessionInvalid)
}

func TestContinueWithSSO_NeverBridgesProjects(t *testing.T) {
	svc, repo := newSSOTestService(t)
	user := seedUser(repo, "alice@example.com", "", "active")

	// The session is minted under a NON-default project; a request scoped
	// to any other project must not light up.
	raw := mintSSO(t, svc, ssoScope("proj-other"), user.ID)

	_, err := svc.ContinueWithSSO(ssoScope("project-a"), raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrSSOSessionInvalid, "a session in one project must not mint codes in another")

	// Same project continues fine (the binding is exact, not a deny-all).
	_, err = svc.ContinueWithSSO(ssoScope("proj-other"), raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.NoError(t, err)
}

func TestContinueWithSSO_ReRunsAccountStatusGate(t *testing.T) {
	svc, repo := newSSOTestService(t)
	user := seedUser(repo, "alice@example.com", "", "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	// The account is suspended AFTER the SSO session was established.
	repo.mu.Lock()
	repo.users[user.ID].Status = "suspended"
	repo.mu.Unlock()

	_, err := svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrAccountNotActive)
}

func TestContinueWithSSO_ReRunsProjectAccessGate(t *testing.T) {
	svc, repo := newSSOTestService(t)
	user := seedUser(repo, "alice@example.com", "", "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	// The project moved to allowlist mode and alice is not on the list.
	restricted := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "project-a",
		Access: ProjectAccessConfig{
			Mode:          AccessModeAllowlist,
			AllowedEmails: []string{"bob@example.com"},
		},
	})
	_, err := svc.ContinueWithSSO(restricted, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
}

func TestContinueWithSSO_ReRunsOriginalLoginPolicy(t *testing.T) {
	svc, repo := newSSOTestService(t)
	// The tenant policy permits ONLY password logins; the SSO session was
	// established via oauth, so continue-as must be refused — the cookie
	// cannot launder a method the policy disallows.
	svc.WithLoginGovernance(withAllowedMethods(LoginMethodPassword))
	user := seedUser(repo, "alice@acme.com", "", "active")
	ctx := ssoScope("proj-1")
	raw := mintSSO(t, svc, ctx, user.ID)

	_, err := svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestContinueWithSSO_SecondFactorRequiredFallsBackToFullLogin(t *testing.T) {
	svc, repo := newSSOTestService(t)
	user := seedUser(repo, "alice@example.com", "", "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	// TOTP was enrolled (or policy tightened) after the session was
	// established: the cookie must not bypass the second factor.
	repo.mu.Lock()
	repo.users[user.ID].TotpRequired = true
	repo.mu.Unlock()

	_, err := svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrSSOSessionInvalid)
}

func TestContinueWithSSO_ReRunsProductAgeGate(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, false)
	svc.cfg.SSOEnabled = true
	svc.cfg.SSOSessionTTLSeconds = 3600
	svc.returnAllow = ParseReturnAllowlist(ssoTestAllowlist)
	// A CHILD-band account (DOB on file, age 8) holding an SSO session.
	user := seedUserAged(t, repo, "kid@example.com", dobAgeMs(8))

	// product-b requires ADULT: continue-as into it must be refused even
	// though the SSO session itself is valid.
	ctx := productScope(t, adultMinimumJSON, "product-b")
	raw := mintSSO(t, svc, ctx, user.ID)
	_, err := svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrProductAgeRestricted)
}

func TestContinueWithSSO_ReturnToMustBeAllowlisted(t *testing.T) {
	svc, repo := newSSOTestService(t)
	user := seedUser(repo, "alice@example.com", "", "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	_, err := svc.ContinueWithSSO(ctx, raw, "https://evil.example.com/steal", "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrInvalidArgument)
}

// ── Credential-kill paths: the SSO session dies with the credential ──────

func TestSSOSessionDiesWithPasswordResetConfirm(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.SSOEnabled = true
	svc.cfg.SSOSessionTTLSeconds = 3600
	svc.returnAllow = ParseReturnAllowlist(ssoTestAllowlist)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	user := seedUser(repo, "alice@example.com", pwHash, "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	token := requestAndExtractResetToken(t, svc, rec, "alice@example.com")
	require.NoError(t, svc.ConfirmPasswordReset(context.Background(), token, "NewStr0ng!Pass"))

	require.False(t, ssoSessionAlive(t, svc, ctx, raw),
		"an SSO session must not survive a password reset")
	// Attacker-repro: the leftover cookie can no longer continue-as.
	_, err := svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrSSOSessionInvalid)
}

func TestSSOSessionDiesWithEmailChangeConfirm(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.SSOEnabled = true
	svc.cfg.SSOSessionTTLSeconds = 3600
	svc.returnAllow = ParseReturnAllowlist(ssoTestAllowlist)
	user := seedUserWithPassword(t, repo, "alice@example.com", "Str0ng!Pass1")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	tok := requestAndExtractChangeToken(t, svc, repo, rec, user.ID, "alice2@example.com", "Str0ng!Pass1")
	_, err := svc.ConfirmEmailChange(context.Background(), tok)
	require.NoError(t, err)

	require.False(t, ssoSessionAlive(t, svc, ctx, raw),
		"an SSO session must not survive an email change")
	_, err = svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrSSOSessionInvalid)
}

func TestSSOSessionDiesWithPlantedCredentialClearing(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	svc.cfg.SSOEnabled = true
	svc.cfg.SSOSessionTTLSeconds = 3600
	svc.returnAllow = ParseReturnAllowlist(ssoTestAllowlist)

	// Unverified account with an attacker-planted password; the real owner
	// then proves inbox control via an emailed OTP, voiding the credential.
	victim := seedUser(repo, "victim@example.com", "hash", "active")
	victim.EmailVerified = false
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, victim.ID)

	require.NoError(t, svc.RequestEmailLoginCode(context.Background(), "victim@example.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)
	_, err := svc.VerifyEmailLoginCode(context.Background(), "victim@example.com", code, "1.1.1.1", "agent")
	require.NoError(t, err)

	require.False(t, ssoSessionAlive(t, svc, ctx, raw),
		"an SSO session must not survive planted-credential clearing")
	_, err = svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrSSOSessionInvalid)
}

func TestSSOSessionDiesWithAccountDeletionRequest(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.SSOEnabled = true
	svc.cfg.SSOSessionTTLSeconds = 3600
	svc.returnAllow = ParseReturnAllowlist(ssoTestAllowlist)
	psvc := newTestProfileServiceForDeletion(repo, newRecordingAuditWriter())
	user := seedUser(repo, "alice@example.com", "hash", "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	_, err := psvc.DeleteMyAccount(context.Background(), user.ID, "no longer needed")
	require.NoError(t, err)

	require.False(t, ssoSessionAlive(t, svc, ctx, raw),
		"an SSO session must not survive a deletion request")
	// Attacker-repro: the deletion must not be silently cancellable from a
	// leftover cookie — the cookie is dead before continue-as could log
	// the user back in and auto-cancel the pending deletion.
	_, err = svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrSSOSessionInvalid)
}

func TestSSOSessionDiesWithAdminDeleteAndPurge(t *testing.T) {
	newSeeded := func(t *testing.T, status string) (*AuthService, *fakeRepo, *User, context.Context, string) {
		t.Helper()
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		svc.cfg.SSOEnabled = true
		svc.cfg.SSOSessionTTLSeconds = 3600
		user := seedUser(repo, "alice@example.com", "hash", status)
		ctx := ssoScope("project-a")
		raw := mintSSO(t, svc, ctx, user.ID)
		return svc, repo, user, ctx, raw
	}

	t.Run("admin delete", func(t *testing.T) {
		svc, repo, user, ctx, raw := newSeeded(t, "active")
		db := newFakeDB()
		db.addUser("admin-1", "admin@example.com", "Admin", "admin", "active")
		admin := newTestAdminServiceWithRepo(db, repo)

		require.NoError(t, admin.DeleteUser(context.Background(), "admin-1", user.ID))
		require.False(t, ssoSessionAlive(t, svc, ctx, raw),
			"an SSO session must not survive an admin delete")
	})

	t.Run("deletion sweeper purge", func(t *testing.T) {
		svc, repo, user, ctx, raw := newSeeded(t, StatusPendingDeletion)
		user.DeletionScheduledAtMs = 100
		admin := newTestAdminServiceWithRepo(newFakeDB(), repo)

		purged, err := admin.PurgeExpiredPendingDeletions(context.Background(), 500, 100)
		require.NoError(t, err)
		require.Equal(t, 1, purged)
		require.False(t, ssoSessionAlive(t, svc, ctx, raw),
			"an SSO session must not survive the deletion-sweeper purge")
	})
}

func TestSSOSessionDiesWithRefreshReplayDetection(t *testing.T) {
	svc, repo := newSSOTestService(t)
	user := seedUser(repo, "alice@example.com", "", "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	rawRefresh, hash := generateRefreshToken()
	_, err := repo.CreateRefreshToken(context.Background(), &RefreshTokenRecord{
		TokenHash: hash, UserID: user.ID, ExpiresAt: svc.nowMs() + 60_000,
	})
	require.NoError(t, err)

	// Legitimate rotation consumes the token…
	_, _, _, err = svc.RefreshToken(context.Background(), rawRefresh, "1.2.3.4", "agent")
	require.NoError(t, err)
	// …and a replay of the consumed token is treated as theft: every
	// derived session store is revoked, SSO included.
	_, _, _, err = svc.RefreshToken(context.Background(), rawRefresh, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrUnauthenticated)

	require.False(t, ssoSessionAlive(t, svc, ctx, raw),
		"an SSO session must not survive refresh-replay detection")
	_, err = svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrSSOSessionInvalid)
}

func TestSSOSessionSurvivesPerProductLogout(t *testing.T) {
	svc, repo := newSSOTestService(t)
	user := seedUser(repo, "alice@example.com", "", "active")
	ctx := ssoScope("project-a")
	raw := mintSSO(t, svc, ctx, user.ID)

	// The user logs out of ONE product (its own refresh token dies)…
	rawRefresh, hash := generateRefreshToken()
	_, err := repo.CreateRefreshToken(context.Background(), &RefreshTokenRecord{
		TokenHash: hash, UserID: user.ID, ExpiresAt: svc.nowMs() + 60_000,
	})
	require.NoError(t, err)
	require.NoError(t, svc.Logout(context.Background(), rawRefresh))

	// …but the SSO session is untouched: continue-as into another product
	// still works.
	require.True(t, ssoSessionAlive(t, svc, ctx, raw))
	_, err = svc.ContinueWithSSO(ctx, raw, ssoTestReturnTo, "1.2.3.4", "agent")
	require.NoError(t, err)
}

func TestSignOutEverywhereKillsSSO(t *testing.T) {
	newSeededProfile := func(t *testing.T) (*fakeRepo, *fakeDB) {
		t.Helper()
		return newFakeRepo(), newFakeDB()
	}

	t.Run("password account requires and accepts the password", func(t *testing.T) {
		repo, db := newSeededProfile(t)
		asvc := newTestAuthService(t, repo)
		pwHash, _ := passwords.Hash("Str0ng!Pass1")
		db.addUserWithPassword("u1", "alice@example.com", "Alice", "member", "active", pwHash)
		ctx := ssoScope("project-a")
		raw := mintSSO(t, asvc, ctx, "u1")
		psvc := newTestProfileServiceWithRepo(repo, db)

		// Wrong password: nothing is revoked.
		_, err := psvc.RevokeAllSessions(context.Background(), "u1", "wrong")
		require.Error(t, err)
		require.True(t, ssoSessionAlive(t, asvc, ctx, raw))

		_, err = psvc.RevokeAllSessions(context.Background(), "u1", "Str0ng!Pass1")
		require.NoError(t, err)
		require.False(t, ssoSessionAlive(t, asvc, ctx, raw),
			"SignOutEverywhere must revoke SSO sessions")
	})

	t.Run("password-less OAuth-only account", func(t *testing.T) {
		repo, db := newSeededProfile(t)
		asvc := newTestAuthService(t, repo)
		// No password credential: there is nothing to confirm with, so the
		// caller's valid access token is the confirmation.
		db.addUser("u2", "bob@example.com", "Bob", "member", "active")
		ctx := ssoScope("project-a")
		raw := mintSSO(t, asvc, ctx, "u2")

		writer := newRecordingAuditWriter()
		psvc := NewProfileService(repo, db, "test-tenant",
			audit.NewLogger(writer, "test-tenant", zap.NewNop()), zap.NewNop())

		_, err := psvc.RevokeAllSessions(context.Background(), "u2", "")
		require.NoError(t, err)
		require.False(t, ssoSessionAlive(t, asvc, ctx, raw),
			"SignOutEverywhere by a password-less account must revoke SSO sessions")

		// The SSO revocation is auditable as its own session-revoked event.
		found := false
		for _, d := range writer.details {
			if strings.Contains(d, "sso_sessions") {
				found = true
			}
		}
		require.True(t, found, "an audit event must mark the SSO revocation")
	})
}
