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
	_, err = svc.ApproveQrLogin(ctx, init.SessionID, true, user.ID, "ApproverAgent")
	require.NoError(t, err)
	res, err := svc.PollQrLogin(ctx, init.SessionID, init.PollSecret, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	authTime := authTimeOf(t, svc, res.AccessToken)
	require.Zero(t, authTime, "a QR session has no sign-in on record")

	_, err = svc.MergeAccounts(ctx, user.ID, authTime, "other@example.com", strongPW, "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrReauthenticationRequired)
	_, newAccess, _, err := svc.RefreshToken(ctx, res.RefreshToken, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Zero(t, authTimeOf(t, svc, newAccess), "nor does its refresh")
}

// The required-DOB step continues the session it interrupted: reached from a
// refresh, it does not turn that refresh into a new sign-in.
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
	_, _, _, err = svc.RefreshToken(ctx, res.RefreshToken, "203.0.113.10", "agent")
	ticket := dobTicketFrom(t, err)
	done, err := svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Zero(t, authTimeOf(t, svc, done.AccessToken), "a refresh behind it: no sign-in")

	seedUser(repo, "dob-signin@example.com", hashPW(t, strongPW), StatusActive)
	svc.nowFunc = func() time.Time { return signedInAt }
	_, err = svc.PasswordLogin(ctx, "dob-signin@example.com", strongPW, "203.0.113.10", "agent")
	svc.nowFunc = time.Now
	ticket = dobTicketFrom(t, err)
	done, err = svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Equal(t, signedInAt.Unix(), authTimeOf(t, svc, done.AccessToken), "the sign-in behind it, not now")
}

// A refresh row from before sessions were anchored has no sign-in on record.
func TestAuthTime_UnanchoredRefreshHasNone(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	seedUser(repo, "legacy@example.com", hashPW(t, strongPW), StatusActive)
	login, err := svc.PasswordLogin(ctx, "legacy@example.com", strongPW, "203.0.113.10", "agent")
	require.NoError(t, err)
	row, err := repo.FindRefreshTokenByHash(ctx, sha256Hex(login.RefreshToken))
	require.NoError(t, err)
	row.SessionStartedAt = 0

	_, access, _, err := svc.RefreshToken(ctx, login.RefreshToken, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Zero(t, authTimeOf(t, svc, access))
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
		// 2^61 * 1000 is 0 mod 2^64: in milliseconds this wrapped to "now",
		// the case a millisecond comparison got wrong.
		"wraps to now in milliseconds": time.Now().Unix() + 1<<61,
		"the largest value":            math.MaxInt64,
	} {
		_, err := svc.MergeAccounts(ctx, survivor.ID, authTime, "bob", accessTestPassword, "203.0.113.10", "agent", false)
		require.ErrorIs(t, err, ErrReauthenticationRequired, name)
	}
}
