//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"
)

func generateTotpCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := otptotp.GenerateCodeCustom(secret, at, otptotp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

func TestE2E_Totp_EnrollVerifyAndDisable(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	email := "totpe2e-disable@example.com"

	// 1. Signup a new user
	at, _, userID := h.Signup(t, email, goodPassword)

	// 2. Begin TOTP Setup
	resp, status := h.rpcCall(t, "BeginTotpSetup", map[string]any{}, at)
	if status != http.StatusOK {
		t.Fatalf("BeginTotpSetup status=%d, body=%v", status, resp)
	}
	secret, _ := resp["secret"].(string)
	if secret == "" {
		t.Fatalf("BeginTotpSetup returned empty secret")
	}
	recoveryCodes, _ := resp["recoveryCodes"].([]any)
	if len(recoveryCodes) != 10 {
		t.Fatalf("recoveryCodes count = %d, want 10", len(recoveryCodes))
	}

	// 3. Verify TOTP Setup
	verifyCode := generateTotpCodeAt(t, secret, time.Now())
	resp, status = h.rpcCall(t, "VerifyTotpSetup", map[string]any{
		"code": verifyCode,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("VerifyTotpSetup status=%d, body=%v", status, resp)
	}
	verified, _ := resp["verified"].(bool)
	if !verified {
		t.Fatalf("expected VerifyTotpSetup to report verified=true")
	}

	// 4. Try normal PasswordLogin — should prompt for TOTP (no tokens, totpRequired: true)
	resp, status = h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    email,
		"password": goodPassword,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("PasswordLogin status=%d, body=%v", status, resp)
	}
	totpReq, _ := resp["totpRequired"].(bool)
	if !totpReq {
		t.Fatalf("expected totpRequired=true, got %v", resp)
	}
	challengeID, _ := resp["loginChallengeId"].(string)
	if challengeID == "" {
		t.Fatalf("expected loginChallengeId to be non-empty")
	}
	if resp["accessToken"] != nil || resp["refreshToken"] != nil {
		t.Fatalf("expected tokens to be empty when totpRequired=true")
	}

	// 5. Verify TOTP to finalize login
	loginCode := generateTotpCodeAt(t, secret, time.Now())
	resp, status = h.rpcCall(t, "VerifyTotp", map[string]any{
		"loginChallengeId": challengeID,
		"code":             loginCode,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("VerifyTotp status=%d, body=%v", status, resp)
	}
	at2, _ := resp["accessToken"].(string)
	rt2, _ := resp["refreshToken"].(string)
	if at2 == "" || rt2 == "" {
		t.Fatalf("expected VerifyTotp to return accessToken and refreshToken")
	}
	userObj, _ := resp["user"].(map[string]any)
	if userObj == nil || userObj["id"] != userID {
		t.Fatalf("user ID mismatch: got %v, want %q", userObj, userID)
	}

	// 6. Disable TOTP
	resp, status = h.rpcCall(t, "DisableTotp", map[string]any{
		"password": goodPassword,
	}, at2)
	if status != http.StatusOK {
		t.Fatalf("DisableTotp status=%d, body=%v", status, resp)
	}

	// 7. Verify login after disabling TOTP (should directly return tokens, totpRequired: false)
	resp, status = h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    email,
		"password": goodPassword,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("PasswordLogin after DisableTotp status=%d, body=%v", status, resp)
	}
	if resp["totpRequired"] != nil && resp["totpRequired"].(bool) {
		t.Fatalf("expected totpRequired to be false/nil after disabling")
	}
	if at3, _ := resp["accessToken"].(string); at3 == "" {
		t.Fatalf("expected password login to return tokens directly after disabling TOTP")
	}
}

func TestE2E_Totp_RegenRecoveryCodesConsumeAndReplayRejected(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	email := "totpe2e-recovery@example.com"

	// 1. Signup and enroll TOTP
	at, _, _ := h.Signup(t, email, goodPassword)
	resp, _ := h.rpcCall(t, "BeginTotpSetup", map[string]any{}, at)
	secret, _ := resp["secret"].(string)
	originalCodesList, _ := resp["recoveryCodes"].([]any)
	var originalCodes []string
	for _, c := range originalCodesList {
		originalCodes = append(originalCodes, c.(string))
	}

	verifyCode := generateTotpCodeAt(t, secret, time.Now())
	_, _ = h.rpcCall(t, "VerifyTotpSetup", map[string]any{"code": verifyCode}, at)

	// 2. Regenerate recovery codes
	resp, status := h.rpcCall(t, "RegenerateRecoveryCodes", map[string]any{
		"password": goodPassword,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("RegenerateRecoveryCodes status=%d, body=%v", status, resp)
	}
	regenCodesList, _ := resp["recoveryCodes"].([]any)
	if len(regenCodesList) != 10 {
		t.Fatalf("regenerated recovery codes count = %d, want 10", len(regenCodesList))
	}
	var regenCodes []string
	for _, c := range regenCodesList {
		regenCodes = append(regenCodes, c.(string))
	}

	// 3. Old recovery code should be invalid
	resp, status = h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    email,
		"password": goodPassword,
	}, "")
	oldChallengeID, _ := resp["loginChallengeId"].(string)

	resp, status = h.rpcCall(t, "VerifyTotp", map[string]any{
		"loginChallengeId": oldChallengeID,
		"code":             originalCodes[0],
	}, "")
	if status == http.StatusOK {
		t.Fatalf("expected old recovery code to be rejected after regeneration")
	}

	// 4. New recovery code should work
	resp, status = h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    email,
		"password": goodPassword,
	}, "")
	validChallengeID, _ := resp["loginChallengeId"].(string)

	resp, status = h.rpcCall(t, "VerifyTotp", map[string]any{
		"loginChallengeId": validChallengeID,
		"code":             regenCodes[0],
	}, "")
	if status != http.StatusOK {
		t.Fatalf("expected regenerated recovery code to work, status=%d, body=%v", status, resp)
	}
	at2, _ := resp["accessToken"].(string)
	if at2 == "" {
		t.Fatalf("expected recovery code login to return accessToken")
	}

	// 5. Replaying the same recovery code must fail
	resp, status = h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    email,
		"password": goodPassword,
	}, "")
	replayChallengeID, _ := resp["loginChallengeId"].(string)

	resp, status = h.rpcCall(t, "VerifyTotp", map[string]any{
		"loginChallengeId": replayChallengeID,
		"code":             regenCodes[0],
	}, "")
	if status == http.StatusOK {
		t.Fatalf("expected replayed recovery code to fail")
	}
}
