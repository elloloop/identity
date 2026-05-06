// Tests for repo-error branches (the `if err != nil { return nil, err }`
// patterns in the service layer). Uses errorRepo to inject failures.
package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/totp"
)

func totpHashCode(s string) string { return totp.HashRecoveryCode(s) }

func TestPasswordSignup_FindUserByEmailErrors(t *testing.T) {
	r := newErrorRepo()
	r.failFindUserByEmail = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.PasswordSignup(context.Background(), "x@example.com", strongPW, "", "")
	require.Error(t, err)
}

func TestPasswordSignup_CreateUserErrors(t *testing.T) {
	r := newErrorRepo()
	r.failCreateUser = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.PasswordSignup(context.Background(), "x@example.com", strongPW, "", "")
	require.Error(t, err)
}

func TestPasswordSignup_IssueTokensFails(t *testing.T) {
	r := newErrorRepo()
	r.failCreateRefreshToken = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.PasswordSignup(context.Background(), "x@example.com", strongPW, "", "")
	require.Error(t, err)
}

func TestPasswordLogin_FindUserErrors(t *testing.T) {
	r := newErrorRepo()
	r.failFindUserByEmail = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.PasswordLogin(context.Background(), "x@example.com", strongPW, "", "")
	require.Error(t, err)
}

func TestPasswordLogin_TotpRequired_CreateChallengeErrors(t *testing.T) {
	r := newErrorRepo()
	pwHash := hashPW(t, strongPW)
	u := seedUser(r.fakeRepo, "totp-fail@example.com", pwHash, "active")
	r.fakeRepo.users[u.ID].TotpRequired = true
	r.failCreateLoginChallenge = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.PasswordLogin(context.Background(), "totp-fail@example.com", strongPW, "", "")
	require.Error(t, err)
}

func TestPasswordLogin_IssueTokensFails(t *testing.T) {
	r := newErrorRepo()
	pwHash := hashPW(t, strongPW)
	seedUser(r.fakeRepo, "issue-fail@example.com", pwHash, "active")
	r.failCreateRefreshToken = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.PasswordLogin(context.Background(), "issue-fail@example.com", strongPW, "", "")
	require.Error(t, err)
}

func TestOAuthLogin_FindUserErrors(t *testing.T) {
	r := newErrorRepo()
	r.failFindUserByEmail = true
	svc := newTestAuthServiceErr(t, r)

	code := fakeOAuthCode("x@example.com", "X", "", "google")
	_, err := svc.OAuthLogin(context.Background(), code, "google", "https://app/cb", "", "", "", "", "")
	require.Error(t, err)
}

func TestOAuthLogin_CreateUserErrors(t *testing.T) {
	r := newErrorRepo()
	r.failCreateUser = true
	svc := newTestAuthServiceErr(t, r)

	code := fakeOAuthCode("x@example.com", "X", "", "google")
	_, err := svc.OAuthLogin(context.Background(), code, "google", "https://app/cb", "", "", "", "", "")
	require.Error(t, err)
}

func TestOAuthLogin_IssueTokensFails(t *testing.T) {
	r := newErrorRepo()
	r.failCreateRefreshToken = true
	svc := newTestAuthServiceErr(t, r)

	code := fakeOAuthCode("x@example.com", "X", "", "google")
	_, err := svc.OAuthLogin(context.Background(), code, "google", "https://app/cb", "", "", "", "", "")
	require.Error(t, err)
}

func TestAcceptInvitation_FindInvitationErrors(t *testing.T) {
	r := newErrorRepo()
	r.failFindInvitationByHash = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.AcceptInvitation(context.Background(), "tok", strongPW, "", "", "")
	require.Error(t, err)
}

func TestAcceptInvitation_GetUserErrors(t *testing.T) {
	r := newErrorRepo()
	u := seedUser(r.fakeRepo, "i-err@example.com", "", "invited")
	rawToken := "invite-tok"
	tokenHash := hashInvitationToken(rawToken)
	seedInvitation(r.fakeRepo, &InvitationRecord{
		TokenHash: tokenHash, Email: "i-err@example.com", UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	r.failGetUser = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "", "", "")
	require.Error(t, err)
}

func TestAcceptInvitation_FindByEmailErrors(t *testing.T) {
	r := newErrorRepo()
	rawToken := "no-uid-tok"
	tokenHash := hashInvitationToken(rawToken)
	seedInvitation(r.fakeRepo, &InvitationRecord{
		TokenHash: tokenHash, Email: "byemail@example.com",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	r.failFindUserByEmail = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "", "", "")
	require.Error(t, err)
}

func TestAcceptInvitation_UpdateUserErrors(t *testing.T) {
	r := newErrorRepo()
	u := seedUser(r.fakeRepo, "upd-err@example.com", "", "invited")
	rawToken := "upd-tok"
	tokenHash := hashInvitationToken(rawToken)
	seedInvitation(r.fakeRepo, &InvitationRecord{
		TokenHash: tokenHash, Email: "upd-err@example.com", UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	r.failUpdateUser = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "", "", "")
	require.Error(t, err)
}

func TestAcceptInvitation_IssueTokensFails(t *testing.T) {
	r := newErrorRepo()
	u := seedUser(r.fakeRepo, "tok-err@example.com", "", "invited")
	rawToken := "tok-fail"
	tokenHash := hashInvitationToken(rawToken)
	seedInvitation(r.fakeRepo, &InvitationRecord{
		TokenHash: tokenHash, Email: "tok-err@example.com", UserID: u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	r.failCreateRefreshToken = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "", "", "")
	require.Error(t, err)
}

func TestRefreshToken_FindErrors(t *testing.T) {
	r := newErrorRepo()
	r.failFindRefreshTokenByHash = true
	svc := newTestAuthServiceErr(t, r)

	_, _, _, err := svc.RefreshToken(context.Background(), "rawtok", "", "")
	require.Error(t, err)
}

func TestRefreshToken_GetUserErrors(t *testing.T) {
	r := newErrorRepo()
	svc := newTestAuthServiceErr(t, r)

	res, err := svc.PasswordSignup(context.Background(), "rt@example.com", strongPW, "", "")
	require.NoError(t, err)

	r.failGetUser = true
	_, _, _, err = svc.RefreshToken(context.Background(), res.RefreshToken, "", "")
	require.Error(t, err)
}

func TestLogout_FindErrors(t *testing.T) {
	r := newErrorRepo()
	r.failFindRefreshTokenByHash = true
	svc := newTestAuthServiceErr(t, r)

	err := svc.Logout(context.Background(), "anything")
	require.Error(t, err)
}

func TestGetCurrentUser_RepoErrors(t *testing.T) {
	r := newErrorRepo()
	r.failGetUser = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.GetCurrentUser(context.Background(), "u")
	require.Error(t, err)
}

// ── Passkey ────────────────────────────────────────────────────────────

func TestBeginPasskeyRegistration_GetUserErrors(t *testing.T) {
	r := newErrorRepo()
	r.failGetUser = true
	svc := newTestAuthServiceErr(t, r)

	_, _, err := svc.BeginPasskeyRegistration(context.Background(), "u", "Key")
	require.Error(t, err)
}

func TestBeginPasskeyRegistration_ListErrors(t *testing.T) {
	r := newErrorRepo()
	seedUser(r.fakeRepo, "x@example.com", "", "active")
	user, _ := r.FindUserByEmail(context.Background(), "x@example.com")
	r.failListPasskeyCredentials = true
	svc := newTestAuthServiceErr(t, r)

	_, _, err := svc.BeginPasskeyRegistration(context.Background(), user.ID, "Key")
	require.Error(t, err)
}

func TestBeginPasskeyRegistration_CreateChallengeErrors(t *testing.T) {
	r := newErrorRepo()
	seedUser(r.fakeRepo, "y@example.com", "", "active")
	user, _ := r.FindUserByEmail(context.Background(), "y@example.com")
	r.failCreatePasskeyChallenge = true
	svc := newTestAuthServiceErr(t, r)

	_, _, err := svc.BeginPasskeyRegistration(context.Background(), user.ID, "Key")
	require.Error(t, err)
}

func TestCompletePasskeyRegistration_ChallengeRepoErrors(t *testing.T) {
	r := newErrorRepo()
	r.failGetPasskeyChallenge = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.CompletePasskeyRegistration(context.Background(), "u", "challenge", "{}", "Device")
	require.Error(t, err)
}

func TestBeginPasskeyLogin_FindUserErrors(t *testing.T) {
	r := newErrorRepo()
	r.failFindUserByEmail = true
	svc := newTestAuthServiceErr(t, r)

	_, _, err := svc.BeginPasskeyLogin(context.Background(), "x@example.com")
	require.Error(t, err)
}

func TestBeginPasskeyLogin_ListPasskeysErrors(t *testing.T) {
	r := newErrorRepo()
	seedUser(r.fakeRepo, "lpk@example.com", "", "active")
	r.failListPasskeyCredentials = true
	svc := newTestAuthServiceErr(t, r)

	_, _, err := svc.BeginPasskeyLogin(context.Background(), "lpk@example.com")
	require.Error(t, err)
}

func TestBeginPasskeyLogin_CreateChallengeErrors(t *testing.T) {
	r := newErrorRepo()
	r.failCreatePasskeyChallenge = true
	svc := newTestAuthServiceErr(t, r)

	_, _, err := svc.BeginPasskeyLogin(context.Background(), "")
	require.Error(t, err)
}

func TestCompletePasskeyLogin_ChallengeRepoErrors(t *testing.T) {
	r := newErrorRepo()
	r.failGetPasskeyChallenge = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.CompletePasskeyLogin(context.Background(), "challenge", "{}", "", "")
	require.Error(t, err)
}

// ── TOTP ───────────────────────────────────────────────────────────────

func TestBeginTotpSetup_GetUserErrors(t *testing.T) {
	r := newErrorRepo()
	r.failGetUser = true
	svc := newTestAuthServiceErr(t, r)

	_, _, _, err := svc.BeginTotpSetup(context.Background(), "u")
	require.Error(t, err)
}

func TestBeginTotpSetup_GetTotpCredErrors(t *testing.T) {
	r := newErrorRepo()
	seedUser(r.fakeRepo, "tg@example.com", "", "active")
	user, _ := r.FindUserByEmail(context.Background(), "tg@example.com")
	r.failGetTotpCredential = true
	svc := newTestAuthServiceErr(t, r)

	_, _, _, err := svc.BeginTotpSetup(context.Background(), user.ID)
	require.Error(t, err)
}

func TestBeginTotpSetup_CreateCredErrors(t *testing.T) {
	r := newErrorRepo()
	seedUser(r.fakeRepo, "tc@example.com", "", "active")
	user, _ := r.FindUserByEmail(context.Background(), "tc@example.com")
	r.failCreateTotpCredential = true
	svc := newTestAuthServiceErr(t, r)

	_, _, _, err := svc.BeginTotpSetup(context.Background(), user.ID)
	require.Error(t, err)
}

func TestBeginTotpSetup_StoreRecoveryErrors(t *testing.T) {
	r := newErrorRepo()
	seedUser(r.fakeRepo, "tr@example.com", "", "active")
	user, _ := r.FindUserByEmail(context.Background(), "tr@example.com")
	r.failDeleteRecoveryCodesForUser = true
	svc := newTestAuthServiceErr(t, r)

	_, _, _, err := svc.BeginTotpSetup(context.Background(), user.ID)
	require.Error(t, err)
}

func TestBeginTotpSetup_CreateRecoveryCodeErrors(t *testing.T) {
	r := newErrorRepo()
	seedUser(r.fakeRepo, "tcr@example.com", "", "active")
	user, _ := r.FindUserByEmail(context.Background(), "tcr@example.com")
	r.failCreateRecoveryCode = true
	svc := newTestAuthServiceErr(t, r)

	_, _, _, err := svc.BeginTotpSetup(context.Background(), user.ID)
	require.Error(t, err)
}

func TestVerifyTotpSetup_GetCredErrors(t *testing.T) {
	r := newErrorRepo()
	r.failGetTotpCredential = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.VerifyTotpSetup(context.Background(), "u", "123456")
	require.Error(t, err)
}

func TestVerifyTotp_GetUserErrors(t *testing.T) {
	r := newErrorRepo()
	seedUser(r.fakeRepo, "vtu@example.com", "", "active")
	user, _ := r.FindUserByEmail(context.Background(), "vtu@example.com")
	cid := "challenge-vtu"
	nid := nextNodeID()
	r.fakeRepo.loginChallenges[nid] = &LoginChallengeRecord{
		NodeID: nid, ChallengeID: cid, UserID: user.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}
	r.failGetUser = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.VerifyTotp(context.Background(), cid, "123456", "", "")
	require.Error(t, err)
}

func TestVerifyTotp_GetTotpCredErrors(t *testing.T) {
	r := newErrorRepo()
	user := seedUser(r.fakeRepo, "vt-tc@example.com", "", "active")
	cid := "challenge-vttc"
	nid := nextNodeID()
	r.fakeRepo.loginChallenges[nid] = &LoginChallengeRecord{
		NodeID: nid, ChallengeID: cid, UserID: user.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}
	r.failGetTotpCredential = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.VerifyTotp(context.Background(), cid, "123456", "", "")
	require.Error(t, err)
}

func TestDisableTotp_GetUserErrors(t *testing.T) {
	r := newErrorRepo()
	r.failGetUser = true
	svc := newTestAuthServiceErr(t, r)

	err := svc.DisableTotp(context.Background(), "u", "p")
	require.Error(t, err)
}

func TestRegenerateRecoveryCodes_GetUserErrors(t *testing.T) {
	r := newErrorRepo()
	r.failGetUser = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.RegenerateRecoveryCodes(context.Background(), "u", "p")
	require.Error(t, err)
}

// ── QR ─────────────────────────────────────────────────────────────────

func TestInitiateQrLogin_RepoErrors(t *testing.T) {
	r := newErrorRepo()
	r.failCreateQrLoginSession = true
	svc := newTestAuthServiceErr(t, r)

	_, _, _, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.Error(t, err)
}

func TestGetQrLoginSession_FindErrors(t *testing.T) {
	r := newErrorRepo()
	r.failFindQrLoginSession = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.GetQrLoginSession(context.Background(), "sid")
	require.Error(t, err)
}

func TestApproveQrLogin_FindErrors(t *testing.T) {
	r := newErrorRepo()
	r.failFindQrLoginSession = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.ApproveQrLogin(context.Background(), "sid", true, "u", "")
	require.Error(t, err)
}

func TestPollQrLogin_FindErrors(t *testing.T) {
	r := newErrorRepo()
	r.failFindQrLoginSession = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.PollQrLogin(context.Background(), "sid", "", "")
	require.Error(t, err)
}

func TestPollQrLogin_GetUserErrors(t *testing.T) {
	r := newErrorRepo()
	user := seedUser(r.fakeRepo, "qrgu@example.com", "", "active")
	svc := newTestAuthServiceErr(t, r)

	sid, _, _, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)
	_, err = svc.ApproveQrLogin(context.Background(), sid, true, user.ID, "")
	require.NoError(t, err)

	r.failGetUser = true
	_, err = svc.PollQrLogin(context.Background(), sid, "", "")
	require.Error(t, err)
}

func TestPollQrLogin_IssueTokensFails(t *testing.T) {
	r := newErrorRepo()
	user := seedUser(r.fakeRepo, "qrtok@example.com", "", "active")
	svc := newTestAuthServiceErr(t, r)

	sid, _, _, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)
	_, err = svc.ApproveQrLogin(context.Background(), sid, true, user.ID, "")
	require.NoError(t, err)

	r.failCreateRefreshToken = true
	_, err = svc.PollQrLogin(context.Background(), sid, "", "")
	require.Error(t, err)
}

func TestPollQrLogin_ExpiredCaseReached(t *testing.T) {
	// Manually create a session with status="expired" to hit the expired switch case.
	r := newErrorRepo()
	svc := newTestAuthServiceErr(t, r)

	r.fakeRepo.mu.Lock()
	id := nextNodeID()
	r.fakeRepo.qrSessions[id] = &QrLoginSessionRecord{
		NodeID: id, SessionID: "expired-sid", Status: "expired",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}
	r.fakeRepo.mu.Unlock()

	res, err := svc.PollQrLogin(context.Background(), "expired-sid", "", "")
	require.NoError(t, err)
	assert.Equal(t, "expired", res.Status)
}

func TestApproveQrLogin_UpdateErrors(t *testing.T) {
	r := newErrorRepo()
	svc := newTestAuthServiceErr(t, r)

	sid, _, _, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)

	r.failUpdateQrLoginSession = true
	_, err = svc.ApproveQrLogin(context.Background(), sid, true, "u", "")
	require.Error(t, err)
}

func TestApproveQrLogin_RejectUpdateErrors(t *testing.T) {
	r := newErrorRepo()
	svc := newTestAuthServiceErr(t, r)

	sid, _, _, err := svc.InitiateQrLogin(context.Background(), "Phone", "", "")
	require.NoError(t, err)

	r.failUpdateQrLoginSession = true
	_, err = svc.ApproveQrLogin(context.Background(), sid, false, "u", "")
	require.Error(t, err)
}

// VerifyTotp with garbage encrypted secret falls through to recovery code path.
func TestVerifyTotp_DecryptFailUsesRecoveryCode(t *testing.T) {
	r := newErrorRepo()
	user := seedUser(r.fakeRepo, "vtdec@example.com", "", "active")

	r.fakeRepo.mu.Lock()
	credID := nextNodeID()
	r.fakeRepo.totpCreds[credID] = &TotpCredRecord{
		NodeID: credID, UserID: user.ID, SecretEncrypted: "not-encrypted-garbage", Verified: true,
	}
	cid := "vtdec-challenge"
	nid := nextNodeID()
	r.fakeRepo.loginChallenges[nid] = &LoginChallengeRecord{
		NodeID: nid, ChallengeID: cid, UserID: user.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}
	// Add a recovery code.
	rcID := nextNodeID()
	rcCode := "ABCD-EFGH-JKLM"
	rcHash := totpHashCode(rcCode)
	r.fakeRepo.recoveryCodes[rcID] = &RecoveryCodeRecord{
		NodeID: rcID, UserID: user.ID, CodeHash: rcHash, Used: false,
	}
	r.fakeRepo.mu.Unlock()

	svc := newTestAuthServiceErr(t, r)
	res, err := svc.VerifyTotp(context.Background(), cid, rcCode, "", "")
	require.NoError(t, err)
	require.NotNil(t, res)
}

// RegenerateRecoveryCodes - storeRecoveryCodes (DeleteRecoveryCodesForUser) errors.
func TestRegenerateRecoveryCodes_StoreErrors(t *testing.T) {
	r := newErrorRepo()
	pwHash := hashPW(t, strongPW)
	user := seedUser(r.fakeRepo, "rcerr@example.com", pwHash, "active")
	r.fakeRepo.users[user.ID].TotpRequired = true

	r.failDeleteRecoveryCodesForUser = true
	svc := newTestAuthServiceErr(t, r)

	_, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID, strongPW)
	require.Error(t, err)
}

// upsertUser update warning path: existing user with name/avatar diff and update fails.
func TestOAuthLogin_ExistingUserUpdateWarns(t *testing.T) {
	r := newErrorRepo()
	seedUser(r.fakeRepo, "ouw@example.com", "", "active")
	r.failUpdateUser = true
	svc := newTestAuthServiceErr(t, r)

	// Should still succeed because the update failure is logged but not propagated.
	code := fakeOAuthCode("ouw@example.com", "Different Name", "https://avatar.png", "google")
	res, err := svc.OAuthLogin(context.Background(), code, "google", "https://app/cb", "", "", "", "", "")
	require.NoError(t, err)
	assert.NotNil(t, res)
}

// ── Friendly device name: Safari branch ────────────────────────────────

func TestFriendlyDeviceName_Safari(t *testing.T) {
	ua := "Mozilla/5.0 (iPhone) Safari/605.1"
	// Has "iphone" + "safari" but no "chrome" — should be Safari.
	result := friendlyDeviceName(ua)
	// browser detection: "safari/" present and !chrome -> Safari
	assert.Equal(t, "Safari on iOS", result)
}
