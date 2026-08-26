package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/secretcrypto"
	"github.com/elloloop/identity/pkg/totp"
)

// ── Chokepoint gate ────────────────────────────────────────────────────

// requireDOBRefusal asserts err is the dob_required refusal and that it
// carries a well-formed completion ticket: signed by the service signer,
// purposed, and naming the dob-less account.
func requireDOBRefusal(t *testing.T, svc *AuthService, err error) {
	t.Helper()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrDOBRequired)
	assert.Contains(t, err.Error(), "dob_required", "the stable wire token must lead the message")
	ticket := dobTicketFrom(t, err)
	// The ticket must NOT verify as an access token — it is a purpose
	// credential, and the shared verifier is what makes that true on every
	// transport, not just in identity's own middleware.
	_, accessErr := jwt.VerifyAccessToken(ticket, svc.signer, "", "", false)
	require.Error(t, accessErr, "a completion ticket must never authenticate a request")
	claims, vErr := jwt.VerifyPurposeToken(ticket, svc.signer, "", "", false, tokenPurposeDOBCompletion)
	require.NoError(t, vErr, "the completion ticket must verify against the service signer")
	assert.Equal(t, tokenPurposeDOBCompletion, claims.Purpose)
	assert.NotEmpty(t, claims.Sub)
}

// dobTicketFrom extracts the completion ticket from a dob_required refusal.
func dobTicketFrom(t *testing.T, err error) string {
	t.Helper()
	var dobErr *DOBRequiredError
	require.ErrorAs(t, err, &dobErr, "the refusal must be a *DOBRequiredError carrying the ticket")
	require.NotEmpty(t, dobErr.Ticket)
	return dobErr.Ticket
}

// dobTicketFor seeds a dob-less password account and drives a login into
// the dob_required refusal, returning the completion ticket.
func dobTicketFor(t *testing.T, svc *AuthService, repo *fakeRepo, email string) string {
	t.Helper()
	seedUser(repo, email, hashPW(t, strongPW), "active")
	_, err := svc.PasswordLogin(context.Background(), email, strongPW, "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
	return dobTicketFrom(t, err)
}

// TestDOBRequired_Chokepoint pins the gate's decision matrix at
// issueTokensWithSessionStart itself — the one place every session-issuing
// path funnels through, so this table is what every per-path test below
// exercises end to end.
func TestDOBRequired_Chokepoint(t *testing.T) {
	tests := []struct {
		name       string
		requireDOB bool
		user       *User
		wantRefuse bool
	}{
		{"flag on, identified, no DOB", true, &User{ID: "u1", Email: "a@b.com", Status: "active"}, true},
		{"flag on, identified, DOB on file", true, &User{ID: "u2", Email: "b@b.com", Status: "active", DateOfBirthMs: dobAgeMs(30)}, false},
		// Anonymous accounts structurally carry no DOB; their age guardrail
		// is the product minimum-age gate, and a CHILD result would strand
		// an email-less account in pending_parental_consent.
		{"flag on, anonymous, no DOB", true, &User{ID: "u3", Status: "active", IsAnonymous: true}, false},
		{"flag off, identified, no DOB", false, &User{ID: "u4", Email: "c@b.com", Status: "active"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			enableAgeGate(t, svc, tc.requireDOB)

			access, refresh, err := svc.issueTokens(context.Background(), tc.user, "", "")
			if !tc.wantRefuse {
				require.NoError(t, err)
				assert.NotEmpty(t, access)
				assert.NotEmpty(t, refresh)
				return
			}
			requireDOBRefusal(t, svc, err)
			assert.Empty(t, access)
			assert.Empty(t, refresh)
			repo.mu.Lock()
			refreshRows := len(repo.refreshTokens)
			sessionRows := len(repo.sessions)
			repo.mu.Unlock()
			assert.Zero(t, refreshRows, "no refresh token may be persisted for a dob-less account")
			assert.Zero(t, sessionRows, "no session row may be persisted for a dob-less account")
		})
	}
}

// ── Per-path plumbing: with the flag on, no path issues tokens to a
// dob-less account ──────────────────────────────────────────────────────

func TestDOBRequired_PasswordLogin(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	seedUser(repo, "nodob@example.com", hashPW(t, strongPW), "active")

	_, err := svc.PasswordLogin(context.Background(), "nodob@example.com", strongPW, "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
}

// PasswordSignup without a DOB under the flag is refused before any
// account exists (the long-standing field-5 rule); with a DOB it passes
// the chokepoint. Both arms pinned here because PasswordSignup is on the
// issue's path list.
func TestDOBRequired_PasswordSignup(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)

	_, err := svc.PasswordSignup(context.Background(), "nodob@example.com", strongPW, "NoDOB", "", 0, "")
	require.ErrorIs(t, err, ErrInvalidArgument)

	res, err := svc.PasswordSignup(context.Background(), "adult@example.com", strongPW, "Adult", "", dobAgeMs(30), "")
	require.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
}

func TestDOBRequired_OAuthLogin(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)

	_, err := svc.OAuthLogin(context.Background(), OAuthLoginParams{
		Code:     fakeOAuthCode("oauth-nodob@example.com", "OAuth", "", "google"),
		Provider: "google", RedirectURI: "https://app/cb",
	})
	requireDOBRefusal(t, svc, err)

	// The JIT account exists but holds no session material.
	got, ferr := repo.FindUserByEmail(context.Background(), "oauth-nodob@example.com")
	require.NoError(t, ferr)
	require.NotNil(t, got)
	repo.mu.Lock()
	n := len(repo.refreshTokens)
	repo.mu.Unlock()
	assert.Zero(t, n)
}

func TestDOBRequired_NativeOAuthLogin(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)
	enableAgeGate(t, svc, true)

	tok := signer.googleToken(t, "g-sub-nodob", "native-nodob@example.com", nativeGoogleAud)
	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "easyloops",
	})
	requireDOBRefusal(t, svc, err)
}

func TestDOBRequired_CompleteHostedOAuth(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	ctx := withProject("proj-1")

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "")
	require.NoError(t, err)
	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)

	// CompleteHostedOAuth mints the session it parks behind the one-time
	// code, so the refusal lands here — no code is issued at all.
	_, err = svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode("hosted-nodob@example.com", "Hosted", "", "google"),
		stateToken, "", "1.2.3.4", "agent", []string{"csrf-123"})
	requireDOBRefusal(t, svc, err)
}

// A one-time code minted before the flag was enabled is still caught when
// redeemed after: the redeem path re-issues through the same chokepoint.
func TestDOBRequired_RedeemOAuthCode(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := withProject("proj-1")

	begin, err := svc.BeginHostedOAuth(ctx, "google",
		"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-123", "")
	require.NoError(t, err)
	stateToken := stateTokenFromAuthURL(t, begin.AuthorizationURL)
	cb, err := svc.CompleteHostedOAuth(ctx, "google",
		fakeOAuthCode("hosted-preflag@example.com", "Hosted", "", "google"),
		stateToken, "", "1.2.3.4", "agent", []string{"csrf-123"})
	require.NoError(t, err)

	enableAgeGate(t, svc, true)

	_, err = svc.RedeemOAuthCode(ctx, cb.Code, "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
}

func TestDOBRequired_VerifyEmailLoginCode(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	enableAgeGate(t, svc, true)
	ctx := context.Background()

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "otp-nodob@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)
	_, err := svc.VerifyEmailLoginCode(ctx, "otp-nodob@test.com", code, "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
}

func TestDOBRequired_RedeemMagicLink(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	enableAgeGate(t, svc, true)
	ctx := context.Background()

	require.NoError(t, svc.RequestMagicLink(ctx, "ml-nodob@test.com", "https://app.test/cb"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)
	_, err := svc.RedeemMagicLink(ctx, token, "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
}

func TestDOBRequired_CompletePasskeySignup(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	enableAgeGate(t, svc, true)
	ctx := context.Background()

	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))

	_, err = svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "My Key", "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
}

func TestDOBRequired_CompletePasskeyLogin(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	ctx := context.Background()

	// Register the credential with the flag off (a pre-flag account), then
	// turn the flag on: the next passkey login must hit the completion step.
	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))
	_, err = svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "My Key", "1.2.3.4", "agent")
	require.NoError(t, err)

	enableAgeGate(t, svc, true)

	_, loginChallengeID, err := svc.BeginPasskeyLogin(ctx, pkVectorEmail)
	require.NoError(t, err)
	setFakeChallengeValue(repo, loginChallengeID, pkB64URL(t, pkLoginChallengeHex))

	_, err = svc.CompletePasskeyLogin(ctx, loginChallengeID, pkAssertionCredentialJSON(t), "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
}

func TestDOBRequired_VerifyTotp(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)

	u := seedUser(repo, "totp-nodob@example.com", hashPW(t, strongPW), "active")
	u.TotpRequired = true

	encrypted, err := secretcrypto.Encrypt("JBSWY3DPEHPK3PXP", testTotpKey())
	require.NoError(t, err)
	recoveryCode := "ABCDEFGHJK"
	repo.mu.Lock()
	credID := nextNodeID()
	repo.totpCreds[credID] = &TotpCredRecord{
		NodeID:          credID,
		UserID:          u.ID,
		SecretEncrypted: encrypted,
		Verified:        true,
	}
	rcID := nextNodeID()
	repo.recoveryCodes[rcID] = &RecoveryCodeRecord{
		NodeID:   rcID,
		UserID:   u.ID,
		CodeHash: totp.HashRecoveryCode(recoveryCode, testTotpRecoveryPepper()),
	}
	lcID := nextNodeID()
	repo.loginChallenges[lcID] = &LoginChallengeRecord{
		NodeID:      lcID,
		ChallengeID: "dob-totp-challenge",
		UserID:      u.ID,
		ExpiresAt:   time.Now().Add(5 * time.Minute).UnixMilli(),
		CreatedAt:   time.Now().UnixMilli(),
	}
	repo.mu.Unlock()

	_, err = svc.VerifyTotp(context.Background(), "dob-totp-challenge", recoveryCode, "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
}

func TestDOBRequired_PollQrLogin(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	user := seedUser(repo, "qr-nodob@example.com", "", "active")
	ctx := context.Background()

	init, err := svc.InitiateQrLogin(ctx, "Pixel 8", "agent", "10.0.0.1")
	require.NoError(t, err)
	_, err = svc.ApproveQrLogin(ctx, init.SessionID, true, user.ID, "ApproverAgent")
	require.NoError(t, err)

	_, err = svc.PollQrLogin(ctx, init.SessionID, init.PollSecret, "10.0.0.1", "agent")
	requireDOBRefusal(t, svc, err)
}

func TestDOBRequired_AcceptInvitation(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	u := seedUser(repo, "invited-nodob@example.com", "", "invited")
	seedInvitation(repo, &InvitationRecord{
		TokenHash: hashInvitationToken("dob-invite-token"),
		Email:     "invited-nodob@example.com",
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	_, err := svc.AcceptInvitation(context.Background(), "dob-invite-token", strongPW, "Invitee", "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
}

// A pre-flag account (created with no DOB while the flag was off) is
// caught at its next refresh — the documented operator-visible consequence
// of turning the flag on.
func TestDOBRequired_RefreshToken(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	res, err := svc.PasswordSignup(context.Background(), "preflag@example.com", strongPW, "Pre", "", 0, "")
	require.NoError(t, err)
	require.NotEmpty(t, res.RefreshToken)

	enableAgeGate(t, svc, true)

	_, _, _, err = svc.RefreshToken(context.Background(), res.RefreshToken, "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)

	// The refusal must be NON-DESTRUCTIVE: the presented refresh token is
	// still unconsumed. If it were burnt, the retry an SDK makes on a failed
	// rotation would land on replay detection, which deletes every refresh
	// token the user has and signs them out on all their devices — a mass
	// logout triggered by turning a flag on.
	stored, err := repo.FindRefreshTokenByHash(context.Background(), sha256Hex(res.RefreshToken))
	require.NoError(t, err)
	require.NotNil(t, stored, "the refusal must leave the refresh token usable")
	require.Zero(t, stored.ConsumedAtMs, "the refusal must not consume the refresh token")

	// A second attempt gets the same refusal, not a replay-detection wipe.
	_, _, _, err = svc.RefreshToken(context.Background(), res.RefreshToken, "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
}

// The anonymous exemption ends the moment the account is promoted: the
// OAuth upgrade re-issues through the chokepoint as an identified account
// and hits the completion step. (The password upgrade arm is already
// refused upfront under the flag — TestUpgradeAnonymousWithPassword_RefusedWhenDOBRequired.)
func TestDOBRequired_AnonymousOAuthUpgrade(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken, "anonymous sessions stay open under the flag (exemption)")

	enableAgeGate(t, svc, true)

	_, err = svc.UpgradeAnonymousWithOAuth(ctx, res.User.ID, oauthCred())
	requireDOBRefusal(t, svc, err)
}

// TestDOBRequired_AdminCreatedAccount pins the CreateUser decision: the
// admin RPC mints no tokens, so nothing is bypassed at creation — but the
// dob-less account it persists (active, password set, no DOB) hits the
// completion step at its first login like any pre-flag account.
func TestDOBRequired_AdminCreatedAccount(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()

	// The record shape admin CreateUser (InviteUser with createImmediately)
	// persists: active, password set, date_of_birth_ms = 0.
	_, err := repo.CreateUser(ctx, &User{
		Email:        "admin-made@example.com",
		Name:         "Admin Made",
		Role:         "member",
		Status:       "active",
		PasswordHash: hashPW(t, strongPW),
	})
	require.NoError(t, err)

	enableAgeGate(t, svc, true)
	_, err = svc.PasswordLogin(ctx, "admin-made@example.com", strongPW, "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
}

// The refusal is audit-logged as a failed login with the dob_required
// reason, so operators can see the gate working.
func TestDOBRequired_AuditsRefusal(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	enableAgeGate(t, svc, true)
	seedUser(repo, "audit-nodob@example.com", hashPW(t, strongPW), "active")

	_, err := svc.PasswordLogin(context.Background(), "audit-nodob@example.com", strongPW, "1.2.3.4", "agent")
	requireDOBRefusal(t, svc, err)
	assert.Equal(t, 1, writer.countByEventTypeAndDetail("login_failure", "reason", "dob_required"))
}

// ── SubmitDateOfBirth ──────────────────────────────────────────────────

func TestSubmitDateOfBirth_AdultCompletesAndCanLogin(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	ctx := context.Background()
	ticket := dobTicketFor(t, svc, repo, "adult@example.com")

	res, err := svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
	assert.Equal(t, "active", res.User.Status)
	assert.False(t, res.User.IsMinor)
	assert.Equal(t, "ADULT", res.User.AgeBand)

	// The DOB is persisted.
	u, err := repo.FindUserByEmail(ctx, "adult@example.com")
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, dobAgeMs(30), u.DateOfBirthMs)

	// The completed account logs in normally — no second completion step.
	login, err := svc.PasswordLogin(ctx, "adult@example.com", strongPW, "1.2.3.4", "agent")
	require.NoError(t, err)
	assert.NotEmpty(t, login.AccessToken)

	// The issued access token is a NORMAL access token (no purpose claim).
	claims, err := jwt.VerifyAccessToken(res.AccessToken, svc.signer, "", "", false)
	require.NoError(t, err)
	assert.Empty(t, claims.Purpose)
}

func TestSubmitDateOfBirth_ChildPendingParentalConsentNoTokens(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	enableAgeGate(t, svc, true)
	ctx := context.Background()
	ticket := dobTicketFor(t, svc, repo, "child@example.com")

	res, err := svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(8), "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.AccessToken, "a child-band completion must not mint tokens")
	assert.Empty(t, res.RefreshToken)
	assert.Equal(t, StatusPendingParentalConsent, res.User.Status)
	assert.True(t, res.User.IsMinor)
	assert.Equal(t, "CHILD", res.User.AgeBand)

	// Persisted: DOB stored, status pending.
	u, err := repo.FindUserByEmail(ctx, "child@example.com")
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, dobAgeMs(8), u.DateOfBirthMs)
	assert.Equal(t, StatusPendingParentalConsent, u.Status)

	// The dead end holds: the pending account cannot password-login.
	_, err = svc.PasswordLogin(ctx, "child@example.com", strongPW, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrAccountNotActive)

	// The completion is audited with the band outcome.
	assert.Equal(t, 1, writer.countByEventTypeAndDetail("login_success", "method", "dob_completion"))
	assert.Equal(t, 1, writer.countByEventTypeAndDetail("login_success", "age_band", "CHILD"))
}

func TestSubmitDateOfBirth_TeenGetsTokensAsMinor(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	ticket := dobTicketFor(t, svc, repo, "teen@example.com")

	res, err := svc.SubmitDateOfBirth(context.Background(), ticket, dobAgeMs(15), "1.2.3.4", "agent")
	require.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.Equal(t, "active", res.User.Status)
	assert.True(t, res.User.IsMinor)
	assert.Equal(t, "TEEN", res.User.AgeBand)
}

func TestSubmitDateOfBirth_ExpiredTicketRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	u := seedUser(repo, "expired-ticket@example.com", hashPW(t, strongPW), "active")

	expired, err := svc.signer.SignAccessToken(context.Background(), jwt.Claims{
		Sub: u.ID, Tenant: svc.defaultTenantID, Purpose: tokenPurposeDOBCompletion,
	}, -time.Minute)
	require.NoError(t, err)

	_, err = svc.SubmitDateOfBirth(context.Background(), expired, dobAgeMs(30), "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
}

// A normal access token is not a completion ticket, and neither is a
// ticket minted for any other purpose.
func TestSubmitDateOfBirth_WrongPurposeRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	u := seedUser(repo, "wrong-purpose@example.com", hashPW(t, strongPW), "active")
	ctx := context.Background()

	accessToken, err := svc.signer.SignAccessToken(ctx, jwt.Claims{
		Sub: u.ID, Tenant: svc.defaultTenantID, Email: u.Email,
	}, 15*time.Minute)
	require.NoError(t, err)
	_, err = svc.SubmitDateOfBirth(ctx, accessToken, dobAgeMs(30), "", "")
	require.ErrorIs(t, err, ErrUnauthenticated, "a normal access token must not complete a DOB")

	otherPurpose, err := svc.signer.SignAccessToken(ctx, jwt.Claims{
		Sub: u.ID, Tenant: svc.defaultTenantID, Purpose: "password_reset",
	}, 10*time.Minute)
	require.NoError(t, err)
	_, err = svc.SubmitDateOfBirth(ctx, otherPurpose, dobAgeMs(30), "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
}

// The ticket's sub is the only account it can complete: completing with
// user A's ticket sets A's DOB and leaves B dob-less.
func TestSubmitDateOfBirth_TicketScopesToItsAccount(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	ctx := context.Background()
	ticketA := dobTicketFor(t, svc, repo, "user-a@example.com")
	seedUser(repo, "user-b@example.com", hashPW(t, strongPW), "active")

	_, err := svc.SubmitDateOfBirth(ctx, ticketA, dobAgeMs(30), "", "")
	require.NoError(t, err)

	a, err := repo.FindUserByEmail(ctx, "user-a@example.com")
	require.NoError(t, err)
	assert.NotZero(t, a.DateOfBirthMs)
	b, err := repo.FindUserByEmail(ctx, "user-b@example.com")
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Zero(t, b.DateOfBirthMs, "another account's DOB must be untouched")
}

func TestSubmitDateOfBirth_AlreadySetRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	ctx := context.Background()
	ticket := dobTicketFor(t, svc, repo, "once@example.com")

	_, err := svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "", "")
	require.NoError(t, err)

	// The ticket still verifies, but the DOB is set: the completion step is
	// not a DOB-change channel.
	_, err = svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(8), "", "")
	require.ErrorIs(t, err, ErrDOBAlreadySet)

	u, ferr := repo.FindUserByEmail(ctx, "once@example.com")
	require.NoError(t, ferr)
	assert.Equal(t, dobAgeMs(30), u.DateOfBirthMs, "the original DOB must survive the replay")
}

func TestSubmitDateOfBirth_InvalidDOBRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)
	ticket := dobTicketFor(t, svc, repo, "baddob@example.com")

	tests := []struct {
		name  string
		dobMs int64
	}{
		{"zero", 0},
		{"negative", -1000},
		{"future", ageGateNow.AddDate(1, 0, 0).UnixMilli()},
		{"implausibly old", ageGateNow.AddDate(-200, 0, 0).UnixMilli()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.SubmitDateOfBirth(context.Background(), ticket, tc.dobMs, "", "")
			require.ErrorIs(t, err, ErrInvalidArgument)
		})
	}

	// None of the rejected attempts stored anything.
	u, err := repo.FindUserByEmail(context.Background(), "baddob@example.com")
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Zero(t, u.DateOfBirthMs)
}

func TestSubmitDateOfBirth_UnknownUserRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)

	ticket, err := svc.signer.SignAccessToken(context.Background(), jwt.Claims{
		Sub: "no-such-user", Tenant: svc.defaultTenantID, Purpose: tokenPurposeDOBCompletion,
	}, 10*time.Minute)
	require.NoError(t, err)

	_, err = svc.SubmitDateOfBirth(context.Background(), ticket, dobAgeMs(30), "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestSubmitDateOfBirth_GarbageTicketRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	enableAgeGate(t, svc, true)

	_, err := svc.SubmitDateOfBirth(context.Background(), "not-a-jwt", dobAgeMs(30), "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
}

// With the flag off, no ticket is ever minted — the pre-flag login of a
// dob-less account succeeds byte-identically to before.
func TestDOBRequired_FlagOff_PreExistingAccountUnaffected(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	seedUser(repo, "legacy@example.com", hashPW(t, strongPW), "active")

	res, err := svc.PasswordLogin(ctx, "legacy@example.com", strongPW, "1.2.3.4", "agent")
	require.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)

	_, _, _, err = svc.RefreshToken(ctx, res.RefreshToken, "1.2.3.4", "agent")
	require.NoError(t, err)
}

// TestDOBCompletion_TicketAndSubmitErrorPaths covers the refusals the happy
// path does not reach: a ticket that fails verification, an out-of-range date,
// and the storage failures on the submit path.
func TestDOBCompletion_TicketAndSubmitErrorPaths(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// Sign up BEFORE the flag so the account is dob-less, then turn the gate
	// on — the pre-flag account the completion step exists for.
	res, err := svc.PasswordSignup(ctx, "dob@example.com", strongPW, "D", "", 0, "")
	require.NoError(t, err)
	user := res.User
	enableAgeGate(t, svc, true)

	// A garbage ticket is refused, and so is a well-formed ACCESS token: the
	// submit path takes purpose tickets only.
	for _, ticket := range []string{"", "not-a-jwt", res.AccessToken} {
		_, err := svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "", "")
		require.ErrorIs(t, err, ErrUnauthenticated, "ticket %q must be refused", ticket)
	}

	ticket, err := svc.mintDOBCompletionTicket(ctx, &User{ID: user.ID})
	require.NoError(t, err)

	// A valid ticket with an out-of-range date is InvalidArgument.
	for _, dob := range []int64{0, svc.nowFunc().Add(48 * time.Hour).UnixMilli()} {
		_, err := svc.SubmitDateOfBirth(ctx, ticket, dob, "", "")
		require.ErrorIs(t, err, ErrInvalidArgument, "dob %d must be refused", dob)
	}

	// Storage failures propagate rather than becoming a denial.
	repo.getUserErr = errConsentInjected
	_, err = svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "", "")
	require.ErrorIs(t, err, errConsentInjected)
	repo.getUserErr = nil

	repo.setDOBOnceErr = errConsentInjected
	_, err = svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "", "")
	require.ErrorIs(t, err, errConsentInjected)
	repo.setDOBOnceErr = nil

	// A ticket for an account that no longer exists refuses without a panic.
	ghostTicket, err := svc.mintDOBCompletionTicket(ctx, &User{ID: "no-such-user"})
	require.NoError(t, err)
	_, err = svc.SubmitDateOfBirth(ctx, ghostTicket, dobAgeMs(30), "", "")
	require.Error(t, err)

	// And the real submission completes the sign-in.
	done, err := svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "", "")
	require.NoError(t, err)
	require.NotEmpty(t, done.AccessToken)
}

// TestSubmitDateOfBirth_IsSetOnce pins the compare-and-set: the completion
// ticket is reusable within its TTL, so two submissions can both read a
// dob-less account. Exactly one may win — otherwise an adult-band submission
// could mint a session while a concurrent child-band one gates the account,
// producing a valid non-minor session on a consent-gated child.
func TestSubmitDateOfBirth_IsSetOnce(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	res, err := svc.PasswordSignup(ctx, "race@example.com", strongPW, "R", "", 0, "")
	require.NoError(t, err)
	enableAgeGate(t, svc, true)

	ticket, err := svc.mintDOBCompletionTicket(ctx, &User{ID: res.User.ID})
	require.NoError(t, err)

	// The child-band submission lands first and gates the account.
	gated, err := svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(8), "", "")
	require.NoError(t, err)
	require.Empty(t, gated.AccessToken, "a child-band completion issues no tokens")

	// The adult-band submission replaying the SAME ticket must not overwrite
	// the stored date, and must not mint a session.
	second, err := svc.SubmitDateOfBirth(ctx, ticket, dobAgeMs(30), "", "")
	require.ErrorIs(t, err, ErrDOBAlreadySet)
	require.Nil(t, second)

	stored, err := repo.GetUser(ctx, res.User.ID)
	require.NoError(t, err)
	require.Equal(t, dobAgeMs(8), stored.DateOfBirthMs, "the losing submission must not overwrite the date")
	require.Equal(t, StatusPendingParentalConsent, stored.Status, "the account must stay gated")
}
