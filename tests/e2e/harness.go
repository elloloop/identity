//go:build e2e

// Package e2e drives the identity service over its public HTTP/JSON
// Connect-RPC wire format — what a downstream JS or Python client sees.
// Tests boot the same handler chain cmd/identity/main.go serves (via
// internal/app + a memory backend) on an in-process httptest server,
// then exercise it with a plain *http.Client + encoding/json. There is
// no import of the Connect-Go client codegen, deliberately — that's
// what distinguishes these tests from tests/integration: the surface
// here is HTTP-only, exactly what a third-party client speaks.
//
// Each test owns its own httptest server (the identity handler is
// cheap to construct) and uses a per-test tenant id, so cases never
// collide.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

// Harness is the bag of resources returned by StartServer. Tests do
// `POST <BaseURL>/identity.IdentityService/<Method>` with a JSON body
// and inspect the JSON response — exactly what a downstream client
// over the wire would do.
type Harness struct {
	BaseURL  string
	HTTP     *http.Client
	TenantID string
	Server   *httptest.Server
	Mailer   *RecordingMailer
}

// RecordingMailer captures every outbound email so tests can inspect
// tokens/codes that the service would normally only deliver through
// SMTP. Safe for concurrent Send under -race: identity sends emails
// from goroutines spawned by audit logging and the sweeper.
type RecordingMailer struct {
	mu       sync.Mutex
	Messages []email.Message
}

// Send records the message and reports success.
func (m *RecordingMailer) Send(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	m.Messages = append(m.Messages, msg)
	m.mu.Unlock()
	return nil
}

// Latest returns the most recently delivered email, or nil if none.
func (m *RecordingMailer) Latest() *email.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Messages) == 0 {
		return nil
	}
	msg := m.Messages[len(m.Messages)-1]
	return &msg
}

// FindContaining returns the most recent email whose Text or HTML body
// contains needle.
func (m *RecordingMailer) FindContaining(needle string) *email.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.Messages) - 1; i >= 0; i-- {
		if strings.Contains(m.Messages[i].Text, needle) || strings.Contains(m.Messages[i].HTML, needle) {
			msg := m.Messages[i]
			return &msg
		}
	}
	return nil
}

// StartServer boots identity with memory-backend defaults sufficient for
// black-box HTTP testing. The server is torn down via t.Cleanup so a
// test never leaks resources between cases.
func StartServer(t *testing.T) *Harness {
	t.Helper()

	tenantID := fmt.Sprintf("e2e-%d", time.Now().UnixNano())

	cfg := &config.Config{
		DefaultTenantID:               tenantID,
		IdentityMode:                  config.IdentityModeSingle,
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "Identity E2E",
		PasskeyOrigin:                 "http://localhost",
		PasskeyChallengeExpirySeconds: 300,
		QRLoginBaseURL:                "http://localhost",
		QRLoginExpirySeconds:          300,
		TOTPIssuer:                    "Identity E2E",
		AllowedOrigins:                "http://localhost",
		AppBaseURL:                    "http://localhost",
		EmailTokenExpirySeconds:       3600,
		SMTPFrom:                      "no-reply@e2e.local",
		PasswordlessSignupEnabled:     true,
		PasswordlessCodeTTLSeconds:    300,
		PasswordlessCodeMaxAttempts:   5,
		EmailSendCooldownSeconds:      0,
		RateLimitPasswordlessPerIP:    10000,
		OAuthAllowedReturnURLs:        "http://localhost",
	}

	store := memory.New()
	mailer := &RecordingMailer{}
	signer := jwttest.NewSigner(t, "e2e-kid")

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}

	built, err := app.New(app.Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               store,
		DB:                 store,
		Passkeys:           pkSvc,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:     mailer,
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	built.Start()
	t.Cleanup(built.Stop)

	srv := httptest.NewServer(built.Handler)
	t.Cleanup(srv.Close)

	return &Harness{
		BaseURL:  srv.URL,
		HTTP:     srv.Client(),
		TenantID: tenantID,
		Server:   srv,
		Mailer:   mailer,
	}
}

// rpcCall posts an RPC request and decodes the JSON response. If the
// HTTP status is non-200 the JSON body is still returned so the test
// can match on Connect-RPC error envelopes (which carry code/message).
func (h *Harness) rpcCall(t *testing.T, method string, req any, accessToken string) (map[string]any, int) {
	t.Helper()

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal %s: %v", method, err)
	}

	url := h.BaseURL + "/identity.IdentityService/" + method
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request %s: %v", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if accessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := h.HTTP.Do(httpReq)
	if err != nil {
		t.Fatalf("rpc %s: %v", method, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", method, err)
	}
	if len(raw) == 0 {
		return nil, resp.StatusCode
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal %s response (status=%d, body=%q): %v", method, resp.StatusCode, string(raw), err)
	}
	return out, resp.StatusCode
}

// Signup is a convenience helper. Returns access+refresh tokens and the user id.
func (h *Harness) Signup(t *testing.T, addr, password string) (accessToken, refreshToken, userID string) {
	t.Helper()
	resp, status := h.rpcCall(t, "PasswordSignup", map[string]any{
		"email":    addr,
		"password": password,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("Signup status=%d body=%v", status, resp)
	}
	at, _ := resp["accessToken"].(string)
	rt, _ := resp["refreshToken"].(string)
	user, _ := resp["user"].(map[string]any)
	uid, _ := user["id"].(string)
	if at == "" || rt == "" || uid == "" {
		t.Fatalf("Signup missing fields: %v", resp)
	}
	return at, rt, uid
}

// Login posts PasswordLogin and returns the token pair on success.
func (h *Harness) Login(t *testing.T, addr, password string) (accessToken, refreshToken string) {
	t.Helper()
	resp, status := h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    addr,
		"password": password,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("Login status=%d body=%v", status, resp)
	}
	at, _ := resp["accessToken"].(string)
	rt, _ := resp["refreshToken"].(string)
	return at, rt
}

// HealthCheck hits the /health endpoint and returns the HTTP status.
func (h *Harness) HealthCheck(t *testing.T, path string) int {
	t.Helper()
	resp, err := h.HTTP.Get(h.BaseURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
