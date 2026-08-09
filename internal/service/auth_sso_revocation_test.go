package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/passwords"
)

// These tests are the regression net for the severe cluster in the SSO gate:
// the browser SSO session is a 90-day rolling fast path to fresh token pairs,
// so EVERY credential-invalidation path must revoke it, not just the one that
// happened to be wired first. Each test plants an SSO session (as a stolen or
// stale __Host-sso_session cookie would be), runs the credential change the
// victim performs to evict an attacker, and proves the fast path is dead.

// ssoMailerService builds an SSO-enabled AuthService over a mailer-backed repo,
// so the same fakeRepo drives both the reset/email-change flows and the SSO
// fast path — they must share a store for the revocation to be observable.
func ssoMailerService(t *testing.T) (*AuthService, *fakeRepo, *recordingTransport) {
	t.Helper()
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.SSOEnabled = true
	svc.cfg.SSOSessionTTLSeconds = 3600
	return svc, repo, rec
}

// plantSSOSession seeds a live SSO session for userID and returns the raw
// cookie value that unlocks it, exactly what an attacker's browser would hold.
func plantSSOSession(t *testing.T, repo *fakeRepo, userID string) string {
	t.Helper()
	raw := "planted-cookie-" + userID
	_, err := repo.CreateSSOSession(context.Background(), &SSOSessionRecord{
		TokenHash:    sha256Hex(raw),
		UserID:       userID,
		LoginMethod:  LoginMethodOAuth,
		CreatedAtMs:  nowMs(),
		LastUsedAtMs: nowMs(),
		ExpiresAtMs:  nowMs() + 3_600_000,
	})
	require.NoError(t, err)
	return raw
}

// extractChangeTokenFromSent finds the confirm-email-change link among all
// sent mails (the notice to the old address carries none) and returns its token.
func extractChangeTokenFromSent(t *testing.T, sent []email.Message) string {
	t.Helper()
	for _, m := range sent {
		if strings.Contains(m.Text, "/auth/confirm-email-change?token=") {
			return extractTokenFromLink(t, m.Text)
		}
	}
	t.Fatalf("no confirm-email-change link among %d mails", len(sent))
	return ""
}

// assertFastPathAlive proves the planted cookie still mints a session, so each
// test starts from a real fast path rather than a vacuous pass.
func assertFastPathAlive(t *testing.T, svc *AuthService, raw string) {
	t.Helper()
	res, err := svc.ContinueSSOSession(context.Background(), raw, "https://app.test/cb", "1.2.3.4", "agent")
	require.NoError(t, err, "the fast path should mint before the credential change")
	require.NotEmpty(t, res.Code)
}

// assertFastPathDead proves the planted cookie can no longer mint anything.
func assertFastPathDead(t *testing.T, svc *AuthService, raw string) {
	t.Helper()
	_, err := svc.ContinueSSOSession(context.Background(), raw, "https://app.test/cb", "1.2.3.4", "agent")
	require.Error(t, err, "the credential change must have killed the fast path")
	require.True(t, errors.Is(err, ErrSSOSessionInvalid) || errors.Is(err, ErrSSOSessionExpired),
		"a revoked session must be reported as gone, got %v", err)
}

func TestSSORevocation_PasswordResetKillsTheFastPath(t *testing.T) {
	svc, repo, rec := ssoMailerService(t)
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	user := seedUser(repo, "victim@test.com", pwHash, "active")

	raw := plantSSOSession(t, repo, user.ID)
	assertFastPathAlive(t, svc, raw)

	token := requestAndExtractResetToken(t, svc, rec, "victim@test.com")
	require.NoError(t, svc.ConfirmPasswordReset(context.Background(), token, "NewStr0ng!Pass"))

	// The whole reason a user resets their password is to evict an attacker;
	// the SSO cookie must not outlive that.
	assertFastPathDead(t, svc, raw)
}

func TestSSORevocation_EmailChangeKillsTheFastPath(t *testing.T) {
	svc, repo, rec := ssoMailerService(t)
	user := seedUserWithPassword(t, repo, "old@test.com", "Str0ng!Pass1")

	raw := plantSSOSession(t, repo, user.ID)
	assertFastPathAlive(t, svc, raw)

	rec.Reset()
	require.NoError(t, svc.RequestEmailChange(context.Background(), user.ID, "new@test.com", "Str0ng!Pass1"))
	// Two mails go out — a notice to the old address (no link) and the
	// confirmation to the new one; pick the one carrying the link.
	token := extractChangeTokenFromSent(t, rec.Sent())
	if _, err := svc.ConfirmEmailChange(context.Background(), token); err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}

	assertFastPathDead(t, svc, raw)
}

func TestSSORevocation_RefreshTokenReplayKillsTheFastPath(t *testing.T) {
	svc, repo, _ := ssoMailerService(t)
	user := seedUserWithPassword(t, repo, "replay@test.com", "Str0ng!Pass1")

	raw := plantSSOSession(t, repo, user.ID)
	assertFastPathAlive(t, svc, raw)

	// A consumed refresh token presented again is treated as theft and forces
	// re-auth for the whole user — the SSO session must go with it.
	_, refresh, err := svc.issueTokens(context.Background(), user, "1.2.3.4", "agent")
	require.NoError(t, err)
	_, _, _, err = svc.RefreshToken(context.Background(), refresh, "1.2.3.4", "agent")
	require.NoError(t, err)
	// Second use of the now-consumed token trips replay detection.
	_, _, _, err = svc.RefreshToken(context.Background(), refresh, "1.2.3.4", "agent")
	require.Error(t, err)

	assertFastPathDead(t, svc, raw)
}

// The package-level revokeAllUserSessions backs DeleteMyAccount, DeactivateUser
// and the purge cascade. DeleteMyAccount is the dangerous caller: a surviving
// cookie would re-authenticate a PENDING_DELETION account and silently cancel
// the erasure. Testing the shared helper covers all three callers at once.
func TestSSORevocation_AccountAccessCutoffRevokesSSO(t *testing.T) {
	repo := newFakeRepo()
	const userID = "user-del"
	raw := plantSSOSession(t, repo, userID)

	before, err := repo.FindSSOSessionByHash(context.Background(), sha256Hex(raw))
	require.NoError(t, err)
	require.True(t, before.Active(nowMs()))

	require.NoError(t, revokeAllUserSessions(context.Background(), repo, userID, nowMs()))

	after, err := repo.FindSSOSessionByHash(context.Background(), sha256Hex(raw))
	require.NoError(t, err)
	require.NotZero(t, after.RevokedAtMs, "the shared cut-off-access helper must revoke SSO sessions")
	require.False(t, after.Active(nowMs()))
}
