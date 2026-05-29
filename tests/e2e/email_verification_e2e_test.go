//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/elloloop/identity/pkg/email"
)

// extractToken pulls ?token=... out of an email body string.
func extractToken(t *testing.T, body string) string {
	t.Helper()
	idx := strings.Index(body, "token=")
	if idx == -1 {
		t.Fatalf("token= not found in body: %q", body)
	}
	rest := body[idx+len("token="):]
	end := len(rest)
	for i, ch := range rest {
		if ch == ' ' || ch == '\n' || ch == '\r' || ch == '"' || ch == '<' {
			end = i
			break
		}
	}
	return rest[:end]
}

// TestE2E_Email_SignupSendsVerification_ThenVerifyEmail verifies the full
// signup email verification flow.
func TestE2E_Email_SignupSendsVerification_ThenVerifyEmail(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	addr := "newverifye2e@example.com"

	// 1. Password Signup
	signup, status := h.rpcCall(t, "PasswordSignup", map[string]any{
		"email":    addr,
		"password": goodPassword,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("PasswordSignup status=%d, body=%v", status, signup)
	}
	at, _ := signup["accessToken"].(string)

	// 2. Read verification email from recorded mailer
	msg := h.Mailer.Latest()
	if msg == nil {
		t.Fatal("no verification email recorded after signup")
	}
	if msg.To != addr {
		t.Errorf("verification email To = %q, want %q", msg.To, addr)
	}
	body := msg.Text
	if body == "" {
		body = msg.HTML
	}
	tok := extractToken(t, body)

	// 3. Verify Email via RPC
	verifyResp, status := h.rpcCall(t, "VerifyEmail", map[string]any{
		"token": tok,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("VerifyEmail status=%d, body=%v", status, verifyResp)
	}
	userObj, _ := verifyResp["user"].(map[string]any)
	if userObj == nil || !userObj["emailVerified"].(bool) {
		t.Errorf("VerifyEmail response did not mark email verified: %v", verifyResp)
	}

	// 4. Confirm with GetCurrentUser
	cur, status := h.rpcCall(t, "GetCurrentUser", map[string]any{}, at)
	if status != http.StatusOK {
		t.Fatalf("GetCurrentUser status=%d, body=%v", status, cur)
	}
	curUser, _ := cur["user"].(map[string]any)
	if curUser == nil || !curUser["emailVerified"].(bool) {
		t.Errorf("GetCurrentUser should report emailVerified=true")
	}
}

// TestE2E_Email_RequestAndConfirmPasswordReset drives the password-reset flow E2E.
func TestE2E_Email_RequestAndConfirmPasswordReset(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	addr := "resete2e@example.com"
	const newPW = "NewPassword!99"

	// 1. Signup
	_, _, _ = h.Signup(t, addr, goodPassword)
	h.Mailer.mu.Lock()
	h.Mailer.Messages = nil // drop verification email noise
	h.Mailer.mu.Unlock()

	// 2. Request Reset
	resp, status := h.rpcCall(t, "RequestPasswordReset", map[string]any{
		"email": addr,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("RequestPasswordReset status=%d, body=%v", status, resp)
	}

	// 3. Read email
	msg := h.Mailer.Latest()
	if msg == nil {
		t.Fatal("no password reset email recorded")
	}
	body := msg.Text
	if body == "" {
		body = msg.HTML
	}
	tok := extractToken(t, body)

	// 4. Confirm Reset
	resp, status = h.rpcCall(t, "ConfirmPasswordReset", map[string]any{
		"token":       tok,
		"newPassword": newPW,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("ConfirmPasswordReset status=%d, body=%v", status, resp)
	}

	// 5. Verify login with new password works
	at, _ := h.Login(t, addr, newPW)
	if at == "" {
		t.Fatalf("login with new password failed")
	}

	// Verify login with old password fails
	_, status = h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    addr,
		"password": goodPassword,
	}, "")
	if status == http.StatusOK {
		t.Fatalf("login with old password unexpectedly succeeded after reset")
	}
}

// TestE2E_EmailChange_FullFlow drives primary email rotation E2E.
func TestE2E_EmailChange_FullFlow(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	oldAddr := "old-e2e@example.com"
	newAddr := "new-e2e@example.com"

	// 1. Signup
	at, rt, _ := h.Signup(t, oldAddr, goodPassword)
	h.Mailer.mu.Lock()
	h.Mailer.Messages = nil // drop verification email noise
	h.Mailer.mu.Unlock()

	// 2. Request Email Change
	resp, status := h.rpcCall(t, "RequestEmailChange", map[string]any{
		"newEmail":        newAddr,
		"currentPassword": goodPassword,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("RequestEmailChange status=%d, body=%v", status, resp)
	}

	// 3. Read emails (should send verify to new, notice to old)
	h.Mailer.mu.Lock()
	msgs := h.Mailer.Messages
	h.Mailer.mu.Unlock()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 emails, got %d", len(msgs))
	}

	var verifyMsg, noticeMsg email.Message
	if msgs[0].To == newAddr {
		verifyMsg, noticeMsg = msgs[0], msgs[1]
	} else {
		verifyMsg, noticeMsg = msgs[1], msgs[0]
	}

	if verifyMsg.To != newAddr {
		t.Errorf("verify To = %q, want %q", verifyMsg.To, newAddr)
	}
	if noticeMsg.To != oldAddr {
		t.Errorf("notice To = %q, want %q", noticeMsg.To, oldAddr)
	}

	body := verifyMsg.Text
	if body == "" {
		body = verifyMsg.HTML
	}
	tok := extractToken(t, body)

	// 4. Confirm Email Change (exempt from auth)
	resp, status = h.rpcCall(t, "ConfirmEmailChange", map[string]any{
		"token": tok,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("ConfirmEmailChange status=%d, body=%v", status, resp)
	}
	userObj, _ := resp["user"].(map[string]any)
	if userObj == nil || userObj["email"] != newAddr {
		t.Errorf("Confirm response email = %v, want %q", userObj["email"], newAddr)
	}
	if !userObj["emailVerified"].(bool) {
		t.Errorf("Confirm response emailVerified = false, want true")
	}

	// 5. Verify refresh token rotation is revoked
	_, status = h.rpcCall(t, "RefreshToken", map[string]any{"refreshToken": rt}, "")
	if status == http.StatusOK {
		t.Errorf("refresh token should have been revoked after email change")
	}

	// 6. Login with new email + same password
	newAt, _ := h.Login(t, newAddr, goodPassword)
	if newAt == "" {
		t.Fatalf("login with new email failed")
	}

	// Old email should fail
	_, status = h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    oldAddr,
		"password": goodPassword,
	}, "")
	if status == http.StatusOK {
		t.Fatalf("login with old email unexpectedly succeeded after change")
	}
}
