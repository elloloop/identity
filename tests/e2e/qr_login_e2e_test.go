//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// TestE2E_QrLogin_HappyPath drives the full QR login flow over Connect-RPC/HTTP/JSON.
func TestE2E_QrLogin_HappyPath(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	// 1. Signup a user who will approve the login
	email := "qr-e2e@example.com"
	signup, status := h.rpcCall(t, "PasswordSignup", map[string]any{
		"email":    email,
		"password": goodPassword,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("PasswordSignup: %d", status)
	}
	approverAt, _ := signup["accessToken"].(string)

	// 2. Initiate QR Login (from Pixel 8)
	resp, status := h.rpcCall(t, "InitiateQrLogin", map[string]any{
		"deviceInfo": "Pixel 8",
		"userAgent":  "Chrome Mobile",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("InitiateQrLogin status=%d, body=%v", status, resp)
	}
	sessionID, _ := resp["sessionId"].(string)
	pollSecret, _ := resp["pollSecret"].(string)
	qrURL, _ := resp["qrUrl"].(string)

	if sessionID == "" || pollSecret == "" || qrURL == "" {
		t.Fatalf("InitiateQrLogin returned empty session/secret/url: %v", resp)
	}
	if !strings.Contains(qrURL, sessionID) {
		t.Errorf("qrUrl %q missing sessionId %q", qrURL, sessionID)
	}

	// 3. Poll QR Login (should return PENDING)
	resp, status = h.rpcCall(t, "PollQrLogin", map[string]any{
		"sessionId":  sessionID,
		"pollSecret": pollSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("PollQrLogin status=%d, body=%v", status, resp)
	}
	statusStr, _ := resp["status"].(string)
	// Status could be camelCased or a string representation of the enum like "QR_LOGIN_STATUS_PENDING"
	if statusStr != "QR_LOGIN_STATUS_PENDING" {
		t.Errorf("expected pending status, got %v", statusStr)
	}

	// 4. Approve QR Login (must be called by the authenticated user)
	resp, status = h.rpcCall(t, "ApproveQrLogin", map[string]any{
		"sessionId": sessionID,
		"approve":   true,
	}, approverAt)
	if status != http.StatusOK {
		t.Fatalf("ApproveQrLogin status=%d, body=%v", status, resp)
	}
	statusStr, _ = resp["status"].(string)
	if statusStr != "QR_LOGIN_STATUS_APPROVED" {
		t.Errorf("expected approved status, got %v", statusStr)
	}

	// 5. Poll again — should be APPROVED and return tokens!
	resp, status = h.rpcCall(t, "PollQrLogin", map[string]any{
		"sessionId":  sessionID,
		"pollSecret": pollSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("PollQrLogin approved status=%d, body=%v", status, resp)
	}
	statusStr, _ = resp["status"].(string)
	if statusStr != "QR_LOGIN_STATUS_APPROVED" {
		t.Errorf("expected approved status from poll, got %v", statusStr)
	}
	at, _ := resp["accessToken"].(string)
	rt, _ := resp["refreshToken"].(string)
	if at == "" || rt == "" {
		t.Fatalf("expected approved poll to return accessToken and refreshToken")
	}

	// 6. Poll again — should be CONSUMED
	resp, status = h.rpcCall(t, "PollQrLogin", map[string]any{
		"sessionId":  sessionID,
		"pollSecret": pollSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("PollQrLogin consumed status=%d, body=%v", status, resp)
	}
	statusStr, _ = resp["status"].(string)
	if statusStr != "QR_LOGIN_STATUS_CONSUMED" {
		t.Errorf("expected consumed status, got %v", statusStr)
	}
}
