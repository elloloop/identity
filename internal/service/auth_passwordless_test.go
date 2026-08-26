package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/passwords"
)

// extractCodeFromEmail pulls the 6-digit OTP out of a rendered code
// email. The text body renders the bare code on its own line.
func extractCodeFromEmail(t *testing.T, body string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		s := strings.TrimSpace(line)
		if len(s) == 6 && isAllDigits(s) {
			return s
		}
	}
	t.Fatalf("no 6-digit code found in body: %q", body)
	return ""
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func passwordlessSvc(t *testing.T) (*AuthService, *fakeRepo, *recordingTransport) {
	t.Helper()
	svc, repo, rec := newAuthSvcWithMailer(t)
	// Magic-link return_to is validated against this allowlist.
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	return svc, repo, rec
}

// ── RequestEmailLoginCode ──────────────────────────────────────────────

func TestRequestEmailLoginCode_SendsCode(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	require.NoError(t, svc.RequestEmailLoginCode(context.Background(), "User@Test.com"))
	sent := rec.Sent()
	require.Len(t, sent, 1)
	assert.Equal(t, "user@test.com", sent[0].To)
	code := extractCodeFromEmail(t, sent[0].Text)
	assert.Len(t, code, 6)
}

func TestRequestEmailLoginCode_UnknownEmailLooksIdentical(t *testing.T) {
	// Anti-enumeration: an unknown email still returns nil and still
	// sends (the account is created only on verify). The caller can't
	// distinguish known from unknown.
	svc, _, rec := passwordlessSvc(t)
	require.NoError(t, svc.RequestEmailLoginCode(context.Background(), "nobody@test.com"))
	assert.Len(t, rec.Sent(), 1)
}

func TestRequestEmailLoginCode_InvalidEmailSilent(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	require.NoError(t, svc.RequestEmailLoginCode(context.Background(), "not-an-email"))
	assert.Empty(t, rec.Sent())
}

func TestRequestEmailLoginCode_PerEmailCooldown(t *testing.T) {
	// Spam control: per-email send cooldown. A second request inside the
	// window does not send.
	svc, _, rec := passwordlessSvc(t)
	svc.emailThrottle = newEmailSendThrottle(60_000, 0)
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "victim@test.com"))
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "victim@test.com"))
	assert.Len(t, rec.Sent(), 1, "second request inside cooldown must not send")
}

// ── VerifyEmailLoginCode ───────────────────────────────────────────────

func TestVerifyEmailLoginCode_AutoCreatesAndIssuesTokens(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "new@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	res, err := svc.VerifyEmailLoginCode(ctx, "new@test.com", code, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
	assert.Equal(t, "new@test.com", res.User.Email)

	// User was created and email marked verified (control was proven).
	got, err := repo.FindUserByEmail(ctx, "new@test.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.EmailVerified)
}

// TestPasswordlessLogin_ClearsPlantedPassword is the passwordless arm of the
// anti-pre-hijacking regression: redeeming an emailed OTP proves control of the
// inbox, so a pre-existing (unverified) password planted by an attacker must be
// cleared, exactly as on the OAuth external-proof path.
func TestPasswordlessLogin_ClearsPlantedPassword(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()

	const plantedPW = "Att@ckerPW1!"
	planted := seedUser(repo, "victim@test.com", hashPW(t, plantedPW), "active")
	planted.EmailVerified = false
	planted.EmailVerifiedAt = 0

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "victim@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	res, err := svc.VerifyEmailLoginCode(ctx, "victim@test.com", code, "9.9.9.9", "agent")
	require.NoError(t, err)
	require.NotNil(t, res)
	// Same pre-existing account, now verified.
	assert.Equal(t, planted.ID, res.User.ID)

	got, err := repo.FindUserByEmail(ctx, "victim@test.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.EmailVerified)
	assert.Empty(t, got.PasswordHash, "planted password must be cleared on OTP-proven email control")

	// The attacker's password no longer works.
	_, err = svc.PasswordLogin(ctx, "victim@test.com", plantedPW, "1.1.1.1", "agent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoPasswordSet))
}

func TestVerifyEmailLoginCode_WrongCodeFails(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "u@test.com"))
	_ = extractCodeFromEmail(t, rec.Sent()[0].Text)

	_, err := svc.VerifyEmailLoginCode(ctx, "u@test.com", "000000", "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
}

func TestVerifyEmailLoginCode_ReplayRejected(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "replay@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	_, err := svc.VerifyEmailLoginCode(ctx, "replay@test.com", code, "", "")
	require.NoError(t, err)
	// Single-use: the same code cannot be verified twice.
	_, err = svc.VerifyEmailLoginCode(ctx, "replay@test.com", code, "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
}

func TestVerifyEmailLoginCode_AttemptCapInvalidatesCode(t *testing.T) {
	// Brute-force cap: after MaxAttempts wrong guesses the code is
	// invalidated, so even the correct code no longer works.
	svc, _, rec := passwordlessSvc(t)
	svc.cfg.PasswordlessCodeMaxAttempts = 3
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "bruteforce@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	for i := 0; i < 3; i++ {
		_, err := svc.VerifyEmailLoginCode(ctx, "bruteforce@test.com", "999999", "", "")
		require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
	}
	// Correct code is now dead because the cap was hit.
	_, err := svc.VerifyEmailLoginCode(ctx, "bruteforce@test.com", code, "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
}

func TestVerifyEmailLoginCode_Expired(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	now := time.Now()
	svc.nowFunc = func() time.Time { return now }
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "exp@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	// Jump past the code TTL (default 5m).
	svc.nowFunc = func() time.Time { return now.Add(10 * time.Minute) }
	_, err := svc.VerifyEmailLoginCode(ctx, "exp@test.com", code, "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
}

// ── Unified-account guarantee ──────────────────────────────────────────

// TestPasswordlessLinksToExistingPasswordAccount is THE unified-account
// test the issue requires: sign up via password, then log in passwordless
// with the same email, and assert the SAME user id — no duplicate.
func TestPasswordlessLinksToExistingPasswordAccount(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()

	signup, err := svc.PasswordSignup(ctx, "shared@test.com", "Str0ng!Passw0rd", "Shared", "", 0, "")
	require.NoError(t, err)
	passwordUserID := signup.User.ID
	require.NotEmpty(t, passwordUserID)
	rec.Reset()

	// OTP arm.
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "shared@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)
	otpRes, err := svc.VerifyEmailLoginCode(ctx, "shared@test.com", code, "", "")
	require.NoError(t, err)
	assert.Equal(t, passwordUserID, otpRes.User.ID, "OTP login must resolve to the password account")

	rec.Reset()
	// Magic-link arm.
	require.NoError(t, svc.RequestMagicLink(ctx, "shared@test.com", "https://app.test/finish"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)
	mlRes, err := svc.RedeemMagicLink(ctx, token, "", "")
	require.NoError(t, err)
	assert.Equal(t, passwordUserID, mlRes.User.ID, "magic-link login must resolve to the password account")

	// Exactly one user with this email exists across all three methods.
	count := 0
	for _, u := range repo.users {
		if u.Email == "shared@test.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "expected exactly one account for the email")
}

// TestPasswordThenPasswordlessSameUser is the cross-method same-account
// assertion stated as a one-liner for clarity in the suite output.
func TestPasswordThenPasswordlessSameUser(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	ctx := context.Background()
	signup, err := svc.PasswordSignup(ctx, "x@test.com", "Str0ng!Passw0rd", "X", "", 0, "")
	require.NoError(t, err)
	rec.Reset()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "x@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)
	res, err := svc.VerifyEmailLoginCode(ctx, "x@test.com", code, "", "")
	require.NoError(t, err)
	assert.Equal(t, signup.User.ID, res.User.ID)
}

// ── Auto-create gate ───────────────────────────────────────────────────

func TestVerifyEmailLoginCode_AutoCreateDisabledRejectsUnknown(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	svc.cfg.PasswordlessSignupEnabled = false
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "stranger@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	_, err := svc.VerifyEmailLoginCode(ctx, "stranger@test.com", code, "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid, "auto-create off: unknown email must not authenticate")

	got, _ := repo.FindUserByEmail(ctx, "stranger@test.com")
	assert.Nil(t, got, "no account should be created when auto-create is disabled")
}

func TestVerifyEmailLoginCode_AutoCreateDisabledStillLogsInExisting(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	svc.cfg.PasswordlessSignupEnabled = false
	ctx := context.Background()
	pwHash, _ := passwords.Hash("Str0ng!Passw0rd")
	existing := seedUser(repo, "member@test.com", pwHash, "active")

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "member@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)
	res, err := svc.VerifyEmailLoginCode(ctx, "member@test.com", code, "", "")
	require.NoError(t, err)
	assert.Equal(t, existing.ID, res.User.ID)
}

// ── RequestMagicLink ───────────────────────────────────────────────────

func TestRequestMagicLink_SendsLink(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	require.NoError(t, svc.RequestMagicLink(context.Background(), "ml@test.com", "https://app.test/cb"))
	sent := rec.Sent()
	require.Len(t, sent, 1)
	assert.Contains(t, sent[0].Text, "/auth/magic-link?token=")
}

func TestRequestMagicLink_RejectsDisallowedReturnTo(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	err := svc.RequestMagicLink(context.Background(), "ml@test.com", "https://evil.test/")
	require.ErrorIs(t, err, ErrInvalidArgument)
	assert.Empty(t, rec.Sent(), "no email on a rejected return_to")
}

func TestRequestMagicLink_PerEmailCooldown(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	svc.emailThrottle = newEmailSendThrottle(60_000, 0)
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "victim@test.com", "https://app.test/cb"))
	require.NoError(t, svc.RequestMagicLink(ctx, "victim@test.com", "https://app.test/cb"))
	assert.Len(t, rec.Sent(), 1)
}

// ── RedeemMagicLink ────────────────────────────────────────────────────

func TestRedeemMagicLink_AutoCreatesAndReturnsTo(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "newml@test.com", "https://app.test/welcome"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	res, err := svc.RedeemMagicLink(ctx, token, "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.Equal(t, "https://app.test/welcome", res.ReturnTo)
	got, _ := repo.FindUserByEmail(ctx, "newml@test.com")
	require.NotNil(t, got)
	assert.True(t, got.EmailVerified)
}

func TestRedeemMagicLink_ReplayRejected(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "rml@test.com", "https://app.test/cb"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	_, err := svc.RedeemMagicLink(ctx, token, "", "")
	require.NoError(t, err)
	_, err = svc.RedeemMagicLink(ctx, token, "", "")
	require.ErrorIs(t, err, ErrMagicLinkInvalid)
}

func TestRedeemMagicLink_UnknownToken(t *testing.T) {
	svc, _, _ := passwordlessSvc(t)
	_, err := svc.RedeemMagicLink(context.Background(), "deadbeef", "", "")
	require.ErrorIs(t, err, ErrMagicLinkInvalid)
}

func TestRedeemMagicLink_AutoCreateDisabledRejectsUnknown(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	svc.cfg.PasswordlessSignupEnabled = false
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "ghost@test.com", "https://app.test/cb"))
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	_, err := svc.RedeemMagicLink(ctx, token, "", "")
	require.ErrorIs(t, err, ErrMagicLinkInvalid)
	got, _ := repo.FindUserByEmail(ctx, "ghost@test.com")
	assert.Nil(t, got)
}

// generateEmailLoginCode must always be a 6-digit string.
func TestGenerateEmailLoginCode_ShapeIsSixDigits(t *testing.T) {
	for i := 0; i < 200; i++ {
		c := generateEmailLoginCode()
		require.Len(t, c, 6)
		require.True(t, isAllDigits(c), "non-digit code: %q", c)
	}
}

// ── Config fallbacks (zero → built-in defaults) ────────────────────────

func TestPasswordlessTTLFallbacks_UseBuiltInDefaults(t *testing.T) {
	svc, _, _ := passwordlessSvc(t)
	svc.cfg.PasswordlessCodeTTLSeconds = 0
	svc.cfg.PasswordlessCodeMaxAttempts = 0
	svc.cfg.PasswordlessMagicLinkTTLSeconds = 0
	assert.Equal(t, defaultEmailCodeTTL, svc.emailCodeTTL())
	assert.Equal(t, int64(defaultCodeMaxAttempts), svc.emailCodeMaxAttempts())
	assert.Equal(t, defaultMagicLinkTTL, svc.magicLinkTTL())
}

// A few wrong guesses below the cap leave the code usable: the correct
// code still verifies (the cap only bites at the configured threshold).
func TestVerifyEmailLoginCode_BelowCapStillUsable(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	svc.cfg.PasswordlessCodeMaxAttempts = 5
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "belowcap@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	for i := 0; i < 2; i++ {
		_, err := svc.VerifyEmailLoginCode(ctx, "belowcap@test.com", "000000", "", "")
		require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
	}
	res, err := svc.VerifyEmailLoginCode(ctx, "belowcap@test.com", code, "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
}

// ── Mailer / persistence failure paths ─────────────────────────────────

// A mailer failure must not surface to the caller (anti-enumeration): the
// code is still stored, so RequestEmailLoginCode returns nil.
func TestRequestEmailLoginCode_MailerFailureSwallowed(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	rec.fail = errTransportFailure
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "mailfail@test.com"))
	got, _ := repo.FindEmailLoginCodeByEmail(ctx, "mailfail@test.com")
	assert.NotNil(t, got, "code persisted even when mail send fails")
}

func TestRequestMagicLink_MailerFailureSwallowed(t *testing.T) {
	svc, _, rec := passwordlessSvc(t)
	rec.fail = errTransportFailure
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "mlfail@test.com", "https://app.test/cb"))
}

// VerifyEmailLoginCode with no outstanding code (never requested) fails.
func TestVerifyEmailLoginCode_NoCodeForEmail(t *testing.T) {
	svc, _, _ := passwordlessSvc(t)
	_, err := svc.VerifyEmailLoginCode(context.Background(), "never@test.com", "123456", "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
}

// Empty / malformed inputs are rejected up front.
func TestVerifyEmailLoginCode_RejectsEmptyInputs(t *testing.T) {
	svc, _, _ := passwordlessSvc(t)
	ctx := context.Background()
	_, err := svc.VerifyEmailLoginCode(ctx, "not-an-email", "123456", "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
	_, err = svc.VerifyEmailLoginCode(ctx, "ok@test.com", "", "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
}

func TestRedeemMagicLink_EmptyToken(t *testing.T) {
	svc, _, _ := passwordlessSvc(t)
	_, err := svc.RedeemMagicLink(context.Background(), "  ", "", "")
	require.ErrorIs(t, err, ErrMagicLinkInvalid)
}

func TestRequestMagicLink_InvalidEmailAfterAllowlistOK(t *testing.T) {
	// A valid return_to but a malformed email is silent (anti-enumeration),
	// after the allowlist check passes.
	svc, _, rec := passwordlessSvc(t)
	require.NoError(t, svc.RequestMagicLink(context.Background(), "bad", "https://app.test/cb"))
	assert.Empty(t, rec.Sent())
}

// errTransportFailure drives the mailer-failure branches.
var errTransportFailure = errors.New("transport failure")

// ── Repo-error propagation ─────────────────────────────────────────────

// When the email lookup itself errors during verify, the error must
// propagate (not silently succeed). Exercises completePasswordlessLogin's
// FindUserByEmail error branch with auto-create disabled.
func TestVerifyEmailLoginCode_LookupErrorPropagates(t *testing.T) {
	repo := newErrorRepo()
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	svc.cfg.PasswordlessSignupEnabled = false
	ctx := context.Background()

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "lookup@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	repo.failFindUserByEmail = true
	_, err := svc.VerifyEmailLoginCode(ctx, "lookup@test.com", code, "", "")
	require.Error(t, err)
}

// When CreateUser fails during auto-create, the error propagates.
func TestVerifyEmailLoginCode_CreateUserErrorPropagates(t *testing.T) {
	repo := newErrorRepo()
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	ctx := context.Background()

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "createfail@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	repo.failCreateUser = true
	_, err := svc.VerifyEmailLoginCode(ctx, "createfail@test.com", code, "", "")
	require.Error(t, err)
}

// A storage failure while persisting the OTP must not surface to the
// caller (anti-enumeration); RequestEmailLoginCode swallows it and no
// email is sent.
func TestRequestEmailLoginCode_StorageFailureSwallowed(t *testing.T) {
	repo := newErrorRepo()
	repo.failUpsertEmailLoginCode = true
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)
	require.NoError(t, svc.RequestEmailLoginCode(context.Background(), "store@test.com"))
	assert.Empty(t, rec.Sent(), "no email when the code could not be stored")
}

// Likewise for the magic-link token.
func TestRequestMagicLink_StorageFailureSwallowed(t *testing.T) {
	repo := newErrorRepo()
	repo.failCreateMagicLinkToken = true
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	require.NoError(t, svc.RequestMagicLink(context.Background(), "store@test.com", "https://app.test/cb"))
	assert.Empty(t, rec.Sent())
}

// A wrong guess whose attempt-increment AND lock-consume both fail is
// still rejected; the failures are logged but never leak. Covers the
// increment-failure and lock-failure branches.
func TestVerifyEmailLoginCode_AttemptBookkeepingFailuresSwallowed(t *testing.T) {
	repo := newErrorRepo()
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)
	svc.cfg.PasswordlessCodeMaxAttempts = 1 // next wrong guess hits the cap
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "bookkeep@test.com"))
	_ = extractCodeFromEmail(t, rec.Sent()[0].Text)

	repo.failIncrEmailLoginCodeAttempts = true
	repo.failConsumeEmailLoginCode = true
	_, err := svc.VerifyEmailLoginCode(ctx, "bookkeep@test.com", "000000", "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
}

// A code already at its attempt cap is rejected on entry (before any hash
// compare). Covers the early cap guard.
func TestVerifyEmailLoginCode_AlreadyAtCapRejected(t *testing.T) {
	svc, repo, _ := passwordlessSvc(t)
	ctx := context.Background()
	_, err := repo.UpsertEmailLoginCode(ctx, &EmailLoginCodeRecord{
		Email: "atcap@test.com", CodeHash: sha256Hex("123456"),
		ExpiresAt: svc.nowMs() + 60_000, CreatedAt: svc.nowMs(),
		AttemptCount: 5, MaxAttempts: 5,
	})
	require.NoError(t, err)
	_, err = svc.VerifyEmailLoginCode(ctx, "atcap@test.com", "123456", "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
}

// A correct code whose single-use consume loses the CAS (e.g. a racing
// replay won) is rejected rather than issuing tokens twice.
func TestVerifyEmailLoginCode_ConsumeRaceLoserRejected(t *testing.T) {
	repo := newErrorRepo()
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	ctx := context.Background()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "consumerace@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	repo.failConsumeEmailLoginCode = true
	_, err := svc.VerifyEmailLoginCode(ctx, "consumerace@test.com", code, "", "")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
}

// RedeemMagicLink propagates a non-sentinel consume error (e.g. a transient
// store failure) rather than masking it as "invalid".
func TestRedeemMagicLink_NonSentinelConsumeErrorPropagates(t *testing.T) {
	repo := newErrorRepo()
	svc, rec := newAuthSvcWithMailerForRepo(t, repo)
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	ctx := context.Background()
	require.NoError(t, svc.RequestMagicLink(ctx, "consumeerr@test.com", "https://app.test/cb"))
	_ = extractTokenFromLink(t, rec.Sent()[0].Text)

	// Fail the user lookup that completePasswordlessLogin performs after a
	// successful consume; the error must propagate.
	token := extractTokenFromLink(t, rec.Sent()[0].Text)
	repo.failFindUserByEmail = true
	_, err := svc.RedeemMagicLink(ctx, token, "", "")
	require.Error(t, err)
}
