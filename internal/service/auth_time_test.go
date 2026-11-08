package service

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/jwt"
)

func authTimeOf(t *testing.T, svc *AuthService, access string) int64 {
	t.Helper()
	claims, err := jwt.VerifyAccessToken(access, svc.signer, "", "", false)
	require.NoError(t, err)
	return claims.AuthTime
}

// A QR handoff proves no credential on the new device: its session carries
// no auth_time, so a stolen session cannot launder itself into a "recent
// sign-in" by approving its own QR login, and a merge from it is refused.
func TestAuthTime_QrHandoffIsNotASignIn(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AccountMergeEnabled = true
	ctx := context.Background()
	user := seedUser(repo, "qr@example.com", "", StatusActive)
	user.EmailVerified = true
	seedUser(repo, "other@example.com", hashPW(t, strongPW), StatusActive).EmailVerified = true

	init, err := svc.InitiateQrLogin(ctx, "Pixel 8", "agent", "203.0.113.10")
	require.NoError(t, err)
	_, err = svc.ApproveQrLogin(ctx, init.SessionID, true, user.ID, "", "ApproverAgent")
	require.NoError(t, err)
	res, err := svc.PollQrLogin(ctx, init.SessionID, init.PollSecret, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	authTime := authTimeOf(t, svc, res.AccessToken)
	require.Zero(t, authTime, "a QR session has no sign-in on record")

	_, err = svc.MergeAccounts(ctx, user.ID, authTime, "other@example.com", strongPW, "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrReauthenticationRequired)
	_, newAccess, _, err := svc.RefreshToken(ctx, res.RefreshToken, "", "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Zero(t, authTimeOf(t, svc, newAccess), "nor does its refresh")
}

// The required-DOB step continues the session it interrupted: reached from a
// refresh, it does not turn that refresh into a new sign-in, and keeps the
// sign-in behind the refresh.
func TestAuthTime_DOBCompletionContinuesTheSession(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	signedInAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	svc.nowFunc = func() time.Time { return signedInAt }
	res, err := svc.PasswordSignup(ctx, "dob-later@example.com", strongPW, "Later", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	svc.nowFunc = time.Now

	enableAgeGate(t, svc, true)
	_, _, _, err = svc.RefreshToken(ctx, res.RefreshToken, "", "203.0.113.10", "agent")
	ticket := dobTicketFrom(t, err)
	done, err := svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Equal(t, signedInAt.Unix(), authTimeOf(t, svc, done.AccessToken), "a refresh behind it: the sign-in that opened the session")
	row, err := repo.FindRefreshTokenByHash(ctx, sha256Hex(done.RefreshToken))
	require.NoError(t, err)
	require.Equal(t, signedInAt.UnixMilli(), row.SessionStartedAt, "the absolute timeout keeps measuring from the sign-in")
	require.Equal(t, signedInAt.UnixMilli(), row.AuthTimeMs, "the next rotation carries the sign-in too")

	seedUser(repo, "dob-signin@example.com", hashPW(t, strongPW), StatusActive)
	svc.nowFunc = func() time.Time { return signedInAt }
	_, err = svc.PasswordLogin(ctx, "dob-signin@example.com", strongPW, "203.0.113.10", "agent")
	svc.nowFunc = time.Now
	ticket = dobTicketFrom(t, err)
	done, err = svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Equal(t, signedInAt.Unix(), authTimeOf(t, svc, done.AccessToken), "the sign-in behind it, not now")
}

// The required-DOB step reached from a refresh is a sign-in for the
// canonical-email gate, as the step's own login_success audit already says:
// a spelling held at sign-in and given up since is rewritten there as a
// sign-in's.
func TestAuthTime_DOBCompletionFromARefreshRewritesAsASignIn(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	ctx := context.Background()
	legacy := legacyGmailAccount(t, repo)
	holder := seedUser(repo, "firstlast@gmail.com", "", StatusDeactivated)
	holder.MergedIntoUserID = "someone-else"

	res := providerSignIn(t, svc)
	require.Equal(t, "first.last@gmail.com", storedUserEmail(t, repo, legacy.ID), "held at sign-in: nothing rewritten")
	holder.MergedIntoUserID = legacy.ID

	enableAgeGate(t, svc, true)
	_, _, _, err := svc.RefreshToken(ctx, res.RefreshToken, "", "203.0.113.10", "agent")
	ticket := dobTicketFrom(t, err)
	_, err = svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Equal(t, "firstlast@gmail.com", storedUserEmail(t, repo, legacy.ID))
	require.Equal(t, 1, writer.countByEventTypeAndDetail("email_canonicalized", "source", "sign_in"))
	require.Equal(t, 0, writer.countByEventTypeAndDetail("email_canonicalized", "source", "session"))
}

// Accepting an invitation proves the mailbox it went to: a sign-in, so its
// session carries auth_time and a refresh keeps it.
func TestAuthTime_AcceptedInvitationIsASignIn(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := context.Background()
	token := seedInvitedUser(t, repo, "invitee@example.com")
	acceptedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	svc.nowFunc = func() time.Time { return acceptedAt }
	res, err := svc.AcceptInvitation(ctx, token, accessTestPassword, "Invitee", "203.0.113.10", "agent")
	require.NoError(t, err)
	svc.nowFunc = time.Now
	require.Equal(t, acceptedAt.Unix(), authTimeOf(t, svc, res.AccessToken))

	_, access, _, err := svc.RefreshToken(ctx, res.RefreshToken, "", "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Equal(t, acceptedAt.Unix(), authTimeOf(t, svc, access), "the refresh keeps the acceptance")
}

// A refresh row from before the sign-in's time was recorded has no sign-in on
// record, so its refreshes carry no auth_time, whether or not it has a
// session-start anchor.
func TestAuthTime_UnanchoredRefreshHasNone(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	seedUser(repo, "legacy@example.com", hashPW(t, strongPW), StatusActive)
	login, err := svc.PasswordLogin(ctx, "legacy@example.com", strongPW, "203.0.113.10", "agent")
	require.NoError(t, err)
	row, err := repo.FindRefreshTokenByHash(ctx, sha256Hex(login.RefreshToken))
	require.NoError(t, err)
	repo.mu.Lock()
	repo.refreshTokens[row.NodeID].SessionStartedAt = 0
	repo.refreshTokens[row.NodeID].AuthTimeMs = 0
	repo.mu.Unlock()

	_, access, _, err := svc.RefreshToken(ctx, login.RefreshToken, "", "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Zero(t, authTimeOf(t, svc, access))
}

// A row anchored before migration 0056 has a session start but no sign-in's
// time on record: its refreshes carry no auth_time until the person signs in
// again, which is what every refreshed token did before the migration.
func TestAuthTime_LegacyAnchoredRowHasNone(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	seedUser(repo, "legacy-anchored@example.com", hashPW(t, strongPW), StatusActive)
	login, err := svc.PasswordLogin(ctx, "legacy-anchored@example.com", strongPW, "203.0.113.10", "agent")
	require.NoError(t, err)
	row, err := repo.FindRefreshTokenByHash(ctx, sha256Hex(login.RefreshToken))
	require.NoError(t, err)
	repo.mu.Lock()
	require.NotZero(t, repo.refreshTokens[row.NodeID].SessionStartedAt, "the anchor stays")
	repo.refreshTokens[row.NodeID].AuthTimeMs = 0
	repo.mu.Unlock()

	_, access, _, err := svc.RefreshToken(ctx, login.RefreshToken, "", "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Zero(t, authTimeOf(t, svc, access), "no sign-in on record")
}

// Completing a required password change continues the sign-in that proved
// the issued password: auth_time is that moment, not the completion.
func TestAuthTime_RequiredPasswordChangeKeepsTheSignIn(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	issuedPasswordUser(t, repo, "issued@example.com")
	signedInAt := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	svc.nowFunc = func() time.Time { return signedInAt }
	ticket := passwordChangeTicket(t, svc, "issued@example.com")
	svc.nowFunc = time.Now

	res, err := svc.CompleteRequiredPasswordChange(context.Background(), ticket, strongPW, "", "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Equal(t, signedInAt.Unix(), authTimeOf(t, svc, res.AccessToken))
}

// An anonymous account proves no credential, and neither does a password it
// chooses for itself; a provider's authentication at upgrade is a sign-in.
func TestAuthTime_AnonymousAccounts(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AuthRequireVerifiedEmail = false
	ctx := anonCtx(true, AccessModeOpen)

	anon, err := svc.SignInAnonymously(ctx, "203.0.113.10", "ua")
	require.NoError(t, err)
	require.Zero(t, authTimeOf(t, svc, anon.AccessToken), "anonymous sign-in")

	up, err := svc.UpgradeAnonymousWithPassword(ctx, anon.User.ID, AnonymousPasswordCredential{
		Email: "upgraded@example.com", Password: "Str0ng-Passw0rd!x",
	})
	require.NoError(t, err)
	require.NotEmpty(t, up.AccessToken)
	require.Zero(t, authTimeOf(t, svc, up.AccessToken), "a password the anonymous session chose")

	anon2, err := svc.SignInAnonymously(ctx, "203.0.113.10", "ua")
	require.NoError(t, err)
	viaProvider, err := svc.UpgradeAnonymousWithOAuth(ctx, anon2.User.ID, oauthCred())
	require.NoError(t, err)
	require.InDelta(t, time.Now().Unix(), authTimeOf(t, svc, viaProvider.AccessToken), 5, "the provider's sign-in")
}

// No auth_time a trusted host forwards, however large, overflows the check.
func TestMergeAccounts_AbsurdAuthTimeIsNotRecent(t *testing.T) {
	svc, _, survivor, _, ctx := mergeFixture(t)
	for name, authTime := range map[string]int64{
		// 2^61 s is 0 mod 2^64 once scaled to milliseconds: a value that
		// lands on "now" under a millisecond comparison.
		"wraps to now in milliseconds": time.Now().Unix() + 1<<61,
		"the largest value":            math.MaxInt64,
	} {
		_, err := svc.MergeAccounts(ctx, survivor.ID, authTime, "bob", accessTestPassword, "203.0.113.10", "agent", false)
		require.ErrorIs(t, err, ErrReauthenticationRequired, name)
	}
}
