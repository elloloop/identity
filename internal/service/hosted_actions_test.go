package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passkeys"
)

// ── Link previews ──────────────────────────────────────────────────────

func TestPeekEmailVerification_ReadyThenUsed(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	ctx := context.Background()
	user := seedUser(repo, "peek-verify@test.com", "x", "active")
	require.NoError(t, svc.SendEmailVerification(ctx, user.ID))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	preview, err := svc.PeekEmailVerification(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, ActionLinkReady, preview.State)
	assert.Equal(t, "peek-verify@test.com", preview.Email)

	// The look consumed nothing: the click still succeeds.
	_, err = svc.VerifyEmail(ctx, token)
	require.NoError(t, err)

	preview, err = svc.PeekEmailVerification(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, ActionLinkUsed, preview.State)
	assert.Equal(t, "peek-verify@test.com", preview.Email, "a used link still names its address")
}

func TestPeekEmailVerification_UnknownAndEmptyAreInvalid(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	for _, token := range []string{"", "no-such-token"} {
		preview, err := svc.PeekEmailVerification(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, ActionLinkInvalid, preview.State)
		assert.Empty(t, preview.Email)
	}
}

func TestPeekEmailVerification_Expired(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	ctx := context.Background()
	user := seedUser(repo, "peek-expired@test.com", "x", "active")
	require.NoError(t, svc.SendEmailVerification(ctx, user.ID))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	svc.nowFunc = func() time.Time { return time.Now().Add(48 * time.Hour) }
	preview, err := svc.PeekEmailVerification(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, ActionLinkExpired, preview.State)
}

func TestPeekPasswordReset_NamesTheAccount(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	ctx := context.Background()
	seedUser(repo, "peek-reset@test.com", hashPW(t, strongPW), "active")
	token := requestAndExtractResetToken(t, svc, rec, "peek-reset@test.com")

	preview, err := svc.PeekPasswordReset(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, ActionLinkReady, preview.State)
	assert.Equal(t, "peek-reset@test.com", preview.Email)

	require.NoError(t, svc.ConfirmPasswordReset(ctx, token, "N3w!Str0ngPassw0rd"))
	preview, err = svc.PeekPasswordReset(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, ActionLinkUsed, preview.State)
}

func TestPeekEmailChange_ShowsTheNewAddress(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	ctx := context.Background()
	user := seedUserWithPassword(t, repo, "peek-old@test.com", "Str0ng!Pass1")
	require.NoError(t, svc.RequestEmailChange(ctx, user.ID, "peek-new@test.com", "Str0ng!Pass1"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	preview, err := svc.PeekEmailChange(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, ActionLinkReady, preview.State)
	assert.Equal(t, "peek-new@test.com", preview.Email)

	_, err = svc.ConfirmEmailChange(ctx, token)
	require.NoError(t, err)
	preview, err = svc.PeekEmailChange(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, ActionLinkUsed, preview.State)
}

func TestPeekMagicLink_ReadyThenUsed(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "peek-ml@test.com", "https://app.test/welcome"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	preview, err := svc.PeekMagicLink(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, ActionLinkReady, preview.State)
	assert.Equal(t, "peek-ml@test.com", preview.Email)

	_, err = svc.RedeemMagicLink(ctx, token, "", "")
	require.NoError(t, err)
	preview, err = svc.PeekMagicLink(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, ActionLinkUsed, preview.State)

	preview, err = svc.PeekMagicLink(ctx, "unknown")
	require.NoError(t, err)
	assert.Equal(t, ActionLinkInvalid, preview.State)
}

func TestPeekInvitation_StatesAndAddressFallback(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	u := seedUser(repo, "peek-invite@example.com", "", "invited")

	// Email on the invitation itself.
	seedInvitation(repo, &InvitationRecord{
		TokenHash: hashInvitationToken("inv-ready"), Email: "peek-invite@example.com", UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), CreatedAt: time.Now().UnixMilli(),
	})
	preview, err := svc.PeekInvitation(ctx, "inv-ready")
	require.NoError(t, err)
	assert.Equal(t, ActionLinkReady, preview.State)
	assert.Equal(t, "peek-invite@example.com", preview.Email)

	// Invitation keyed by user only: the address comes from the account.
	seedInvitation(repo, &InvitationRecord{
		TokenHash: hashInvitationToken("inv-by-user"), UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), CreatedAt: time.Now().UnixMilli(),
	})
	preview, err = svc.PeekInvitation(ctx, "inv-by-user")
	require.NoError(t, err)
	assert.Equal(t, "peek-invite@example.com", preview.Email)

	seedInvitation(repo, &InvitationRecord{
		TokenHash: hashInvitationToken("inv-expired"), Email: "peek-invite@example.com", UserID: u.ID,
		ExpiresAt: time.Now().Add(-time.Hour).UnixMilli(), CreatedAt: time.Now().UnixMilli(),
	})
	preview, err = svc.PeekInvitation(ctx, "inv-expired")
	require.NoError(t, err)
	assert.Equal(t, ActionLinkExpired, preview.State)

	seedInvitation(repo, &InvitationRecord{
		TokenHash: hashInvitationToken("inv-used"), Email: "peek-invite@example.com", UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), AcceptedAt: time.Now().UnixMilli(), CreatedAt: time.Now().UnixMilli(),
	})
	preview, err = svc.PeekInvitation(ctx, "inv-used")
	require.NoError(t, err)
	assert.Equal(t, ActionLinkUsed, preview.State)

	preview, err = svc.PeekInvitation(ctx, "inv-unknown")
	require.NoError(t, err)
	assert.Equal(t, ActionLinkInvalid, preview.State)
}

// ── Magic-link handover ────────────────────────────────────────────────

func (r *fakeRepo) refreshTokenCountForUser(userID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, t := range r.refreshTokens {
		if t.UserID == userID {
			n++
		}
	}
	return n
}

func (r *fakeRepo) handoverCodes() []*OAuthOneTimeCodeRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*OAuthOneTimeCodeRecord, 0, len(r.oauthOneTimeCodes))
	for _, c := range r.oauthOneTimeCodes {
		cp := *c
		out = append(out, &cp)
	}
	return out
}

// TestRedeemMagicLinkForHandover_MintsCodeNotSession: the hosted page's
// redeem establishes the user and mints a magic-link handover code, and
// issues no session of its own — the app gets one by redeeming the code,
// exactly once, as a passwordless login.
func TestRedeemMagicLinkForHandover_MintsCodeNotSession(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "handover@test.com", "https://app.test/welcome?next=/home"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	handover, err := svc.RedeemMagicLinkForHandover(ctx, token, "203.0.113.9", "UA/1")
	require.NoError(t, err)
	assert.Equal(t, "https://app.test/welcome?next=/home", handover.ReturnTo)
	assert.NotEmpty(t, handover.Code)
	assert.Contains(t, handover.RedirectURL, "https://app.test/welcome?")
	assert.Contains(t, handover.RedirectURL, "code="+handover.Code)
	assert.Contains(t, handover.RedirectURL, "next=%2Fhome")

	user, err := repo.FindUserByEmail(ctx, "handover@test.com")
	require.NoError(t, err)
	require.NotNil(t, user, "control of the inbox creates the account")
	assert.True(t, user.EmailVerified)
	assert.Equal(t, 0, repo.refreshTokenCountForUser(user.ID), "the page must not mint a session nobody receives")

	codes := repo.handoverCodes()
	require.Len(t, codes, 1)
	assert.Equal(t, HandoverMethodMagicLink, codes[0].LoginMethod)
	assert.Equal(t, user.ID, codes[0].UserID)

	// The magic link itself is spent.
	_, err = svc.RedeemMagicLinkForHandover(ctx, token, "", "")
	require.ErrorIs(t, err, ErrMagicLinkInvalid)

	// The app redeems the code once and gets a session.
	result, err := svc.RedeemOAuthCode(ctx, handover.Code, "203.0.113.9", "UA/1")
	require.NoError(t, err)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, user.ID, result.User.ID)
	assert.Equal(t, 1, repo.refreshTokenCountForUser(user.ID))

	_, err = svc.RedeemOAuthCode(ctx, handover.Code, "", "")
	require.ErrorIs(t, err, ErrOAuthCodeInvalid, "a handover code is single-use")
}

// TestRedeemMagicLinkForHandover_AuditsAsPasswordlessLogin: redeeming a
// magic-link handover code records a passwordless login, not an OAuth one.
func TestRedeemMagicLinkForHandover_AuditsAsPasswordlessLogin(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	cfg := testConfig()
	cfg.AppBaseURL = "https://app.test"
	cfg.SMTPFrom = "no-reply@test.local"
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin})
	require.NoError(t, err)
	mail := &recordingTransport{}
	svc := NewAuthServiceWithOAuth(
		repo, cfg, testKeyRing(t), pk,
		audit.NewLogger(writer, "test-tenant", nil),
		testTotpKey(), testTotpRecoveryPepper(), mail, nil, zap.NewNop(),
		nil, // no OAuth at all: the hosted flow alone must carry the handover
	)
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	ctx := context.Background()

	require.NoError(t, svc.RequestMagicLink(ctx, "audit-ml@test.com", "https://app.test/cb"))
	token := extractTokenFromLink(t, mail.Sent()[0].Text)
	handover, err := svc.RedeemMagicLinkForHandover(ctx, token, "", "")
	require.NoError(t, err)

	_, err = svc.RedeemOAuthCode(ctx, handover.Code, "", "")
	require.NoError(t, err)
	assert.Equal(t, 1, writer.countByEventTypeAndDetail("login_success", "method", HandoverMethodMagicLink))
	assert.Equal(t, 0, writer.countByEventType("oauth_login"))
}

// TestRedeemMagicLinkForHandover_StaleReturnToRefused: a return_to the
// allowlist no longer admits is not redirected to; the token is spent so the
// link cannot be retried against a later, looser configuration either.
func TestRedeemMagicLinkForHandover_StaleReturnToRefused(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "stale@test.com", "https://app.test/welcome"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	svc.returnAllow = ParseReturnAllowlist("https://other.test/")
	_, err := svc.RedeemMagicLinkForHandover(ctx, token, "", "")
	require.ErrorIs(t, err, ErrMagicLinkInvalid)
	assert.Empty(t, repo.handoverCodes())
	got, _ := repo.FindUserByEmail(ctx, "stale@test.com")
	assert.Nil(t, got, "no account is created for a link that cannot complete")
}

func TestRedeemMagicLinkForHandover_SignupDisabledUnknownEmail(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	svc.cfg.PasswordlessSignupEnabled = false
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "ghost-handover@test.com", "https://app.test/cb"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	_, err := svc.RedeemMagicLinkForHandover(ctx, token, "", "")
	require.ErrorIs(t, err, ErrMagicLinkInvalid)
	got, _ := repo.FindUserByEmail(ctx, "ghost-handover@test.com")
	assert.Nil(t, got)
	assert.Empty(t, repo.handoverCodes())
}

func TestRedeemMagicLinkForHandover_EmptyAndUnknownToken(t *testing.T) {
	svc, _, _ := passwordlessSvc(t)
	for _, token := range []string{"", "  ", "unknown"} {
		_, err := svc.RedeemMagicLinkForHandover(context.Background(), token, "", "")
		require.ErrorIs(t, err, ErrMagicLinkInvalid)
	}
}

// ── Handover code redeem ───────────────────────────────────────────────

// TestRedeemOAuthCode_UnknownMethodRefused: a code whose minting flow is not
// one redeem knows is refused rather than completed under a guessed policy.
func TestRedeemOAuthCode_UnknownMethodRefused(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	user := seedUser(repo, "bogus-method@test.com", "", "active")
	_, err := repo.CreateOAuthOneTimeCode(ctx, &OAuthOneTimeCodeRecord{
		CodeHash: sha256Hex("bogus"), UserID: user.ID, LoginMethod: "telepathy",
		ExpiresAt: svc.nowMs() + 60_000, CreatedAt: svc.nowMs(),
	})
	require.NoError(t, err)

	_, err = svc.RedeemOAuthCode(ctx, "bogus", "", "")
	require.ErrorIs(t, err, ErrOAuthCodeInvalid)
	assert.Equal(t, 0, repo.refreshTokenCountForUser(user.ID))
}

// TestRedeemOAuthCode_AvailableWithHostedFlowOnly: the return allowlist
// alone enables the hosted magic-link page, so redeem must be reachable
// without any OAuth provider; an unknown code is then invalid, not
// "OAuth disabled".
func TestRedeemOAuthCode_AvailableWithHostedFlowOnly(t *testing.T) {
	svc := newTestAuthServiceNoOAuth(t, newFakeRepo())
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	_, err := svc.RedeemOAuthCode(context.Background(), "nonexistent", "", "")
	require.ErrorIs(t, err, ErrOAuthCodeInvalid)
}

func TestHandoverProfile(t *testing.T) {
	method, event, ok := handoverProfile(HandoverMethodOAuth)
	require.True(t, ok)
	assert.Equal(t, LoginMethodOAuth, method)
	assert.Equal(t, "oauth_login", string(event))

	method, event, ok = handoverProfile(HandoverMethodMagicLink)
	require.True(t, ok)
	assert.Equal(t, LoginMethodEmailOTP, method)
	assert.Equal(t, "login_success", string(event))

	for _, m := range []string{"", "password", "OAUTH"} {
		_, _, ok := handoverProfile(m)
		assert.False(t, ok, "%q must not map to a profile", m)
	}
}

// ── Invitation redeem ──────────────────────────────────────────────────

// TestRedeemInvitation_ActivatesWithoutSession: the hosted page's redeem
// does everything AcceptInvitation does except mint tokens, and the new
// member then signs in with the password they chose.
func TestRedeemInvitation_ActivatesWithoutSession(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	u := seedUser(repo, "redeem-invite@example.com", "", "invited")
	seedInvitation(repo, &InvitationRecord{
		TokenHash: hashInvitationToken("inv-redeem"), Email: "redeem-invite@example.com", UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), CreatedAt: time.Now().UnixMilli(),
	})

	user, err := svc.RedeemInvitation(ctx, "inv-redeem", strongPW, " New Member ")
	require.NoError(t, err)
	assert.Equal(t, "active", user.Status)
	assert.Equal(t, "New Member", user.Name)
	assert.Equal(t, 0, repo.refreshTokenCountForUser(user.ID), "no session is minted for a server-rendered page")

	_, err = svc.RedeemInvitation(ctx, "inv-redeem", strongPW, "")
	require.ErrorIs(t, err, ErrInvitationUsed)

	login, err := svc.PasswordLogin(ctx, "redeem-invite@example.com", strongPW, "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, login.AccessToken)
}

func TestRedeemInvitation_WeakPasswordLeavesInvitationLive(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	u := seedUser(repo, "weak-invite@example.com", "", "invited")
	seedInvitation(repo, &InvitationRecord{
		TokenHash: hashInvitationToken("inv-weak"), Email: "weak-invite@example.com", UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), CreatedAt: time.Now().UnixMilli(),
	})
	_, err := svc.RedeemInvitation(ctx, "inv-weak", "short", "")
	require.ErrorIs(t, err, ErrWeakPassword)
	assert.True(t, strings.Contains(err.Error(), "Password must"), "the requirement that failed is named: %v", err)

	_, err = svc.RedeemInvitation(ctx, "inv-weak", strongPW, "")
	require.NoError(t, err)
}

// ── Branding ───────────────────────────────────────────────────────────

func TestHostedUIBranding_ProjectOverridesGlobal(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())
	svc.cfg.EmailBrandProductName = "Global Product"
	svc.cfg.EmailBrandSupportEmail = "help@global.test"

	got := svc.HostedUIBranding(context.Background())
	assert.Equal(t, HostedUIBranding{ProductName: "Global Product", SupportEmail: "help@global.test"}, got)

	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "proj-kids",
		Branding:  ProjectBrandingConfig{ProductName: "Kids", SupportEmail: "help@kids.test"},
	})
	got = svc.HostedUIBranding(ctx)
	assert.Equal(t, HostedUIBranding{ProductName: "Kids", SupportEmail: "help@kids.test"}, got)
}

// TestRedeemMagicLinkForHandover_StaleReturnToLeavesLinkUnspent: the
// allowlist is checked before the token is consumed, so a configuration
// change refuses the click without burning a live link — the same link
// redeems once the allowlist admits its return_to again.
func TestRedeemMagicLinkForHandover_StaleReturnToLeavesLinkUnspent(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "unspent@test.com", "https://app.test/welcome"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	svc.returnAllow = ParseReturnAllowlist("https://other.test/")
	_, err := svc.RedeemMagicLinkForHandover(ctx, token, "", "")
	require.ErrorIs(t, err, ErrMagicLinkInvalid)

	preview, err := svc.PeekMagicLink(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, ActionLinkReady, preview.State, "a refused click must not spend the token")

	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	handover, err := svc.RedeemMagicLinkForHandover(ctx, token, "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, handover.Code)
}

// TestRedeemMagicLinkForHandover_AuditsTheConsume: proving control of the
// inbox (and creating the account) is audited when the link is consumed,
// whether or not the app ever redeems the code.
func TestRedeemMagicLinkForHandover_AuditsTheConsume(t *testing.T) {
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	cfg := testConfig()
	cfg.AppBaseURL = "https://app.test"
	cfg.SMTPFrom = "no-reply@test.local"
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin})
	require.NoError(t, err)
	mail := &recordingTransport{}
	svc := NewAuthServiceWithOAuth(repo, cfg, testKeyRing(t), pk, audit.NewLogger(writer, "test-tenant", nil),
		testTotpKey(), testTotpRecoveryPepper(), mail, nil, zap.NewNop(), nil)
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	ctx := context.Background()

	require.NoError(t, svc.RequestMagicLink(ctx, "audit-consume@test.com", "https://app.test/cb"))
	_, err = svc.RedeemMagicLinkForHandover(ctx, extractTokenFromLink(t, mail.Sent()[0].Text), "", "")
	require.NoError(t, err)
	assert.Equal(t, 1, writer.countByEventType(string(audit.EventMagicLinkConsumed)))
	assert.Equal(t, 1, writer.countByEventTypeAndDetail(string(audit.EventMagicLinkConsumed), "via", "hosted_handover"))
	assert.Equal(t, 0, writer.countByEventType("login_success"), "the sign-in itself is audited at redeem")
}

func TestWeakPasswordError_UnwrapsAndCarriesIssues(t *testing.T) {
	err := passwordIssuesToErr([]string{"Password must be at least 12 characters", "Password is too common"})
	require.ErrorIs(t, err, ErrWeakPassword)
	var weak *WeakPasswordError
	require.ErrorAs(t, err, &weak)
	assert.Equal(t, []string{"Password must be at least 12 characters", "Password is too common"}, weak.Issues)
	assert.Equal(t, "password does not meet strength requirements: Password must be at least 12 characters; Password is too common", err.Error())
	assert.NoError(t, passwordIssuesToErr(nil))
}
