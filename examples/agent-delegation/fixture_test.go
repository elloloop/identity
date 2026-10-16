package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// This fixture is a test binary, never a production executable or account.
func TestBrowserFixture(t *testing.T) {
	if os.Getenv("IDENTITY_BROWSER_FIXTURE") != "1" {
		t.Skip("browser harness only")
	}
	const resource = "https://files.example.test"
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	defer server.Close()
	cfg := &config.Config{DefaultTenantID: "tenant", DefaultProjectID: config.DefaultProjectIDFallback, DefaultProjectAccessMode: service.AccessModeOpen, AuthAllowLocal: true, PasswordSignupEnabled: true, PasswordResetEnabled: true, JWTExpirySeconds: 900, RefreshExpirySeconds: 604800, LoginMaxFailedAttempts: 100, LoginLockoutSeconds: 900, LoginChallengeExpirySeconds: 300, PasskeyRPID: "localhost", PasskeyRPName: "Identity test", PasskeyOrigin: "http://localhost:9002", PasskeyChallengeExpirySeconds: 300, TOTPIssuer: "Identity test", JWTIssuer: "https://auth.example.test", AgentsEnabled: true, AgentOAuthEnabled: true, RevocationMode: config.RevocationModeSession, AgentOAuthAccessSeconds: 300, AgentOAuthConsentSeconds: 86400, AgentOAuthRefreshIdleSeconds: 3600}
	cfg.AssuranceEnabled = true
	cfg.AssuranceChallengeTTLSeconds = 300
	cfg.AssuranceTurnstileSecret = "offline-provider-fixture-secret"
	cfg.AssuranceWebProvider = config.AssuranceWebProviderTurnstile
	cfg.AssuranceTurnstileSiteKey = "browser-test-public-site-key"
	cfg.AssuranceEnforcePasswordLogin = true
	cfg.AssuranceWebTokenTTLSeconds = 300
	cfg.AssuranceTokenTTLSeconds = 300
	cfg.AllowedOrigins = "http://" + server.Listener.Addr().String()
	sum := sha256.Sum256([]byte("offline-resource-test-secret"))
	cfg.AgentOAuthResourceCredentialsJSON = fmt.Sprintf(`[{"id":"files-resource","project_id":"%s","resource":"%s","secret_sha256":"%s"}]`, cfg.DefaultProjectID, resource, hex.EncodeToString(sum[:]))
	repo := memory.New()
	signer := jwttest.NewSigner(t, "browser-test-key")
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Identity test", Origin: "http://localhost:9002"})
	require.NoError(t, err)
	built, err := app.New(app.Deps{AssuranceWebVerifier: browserAssuranceVerifier{}, Config: cfg, Logger: zap.NewNop(), Signer: signer, Repo: repo, DB: repo, Passkeys: pk, TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("offline-recovery-pepper-0123456789012345")})
	require.NoError(t, err)
	mux.Handle("/", built.Handler)
	server.Start()
	client := identityconnect.NewIdentityServiceClient(server.Client(), server.URL)
	signed, err := client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{Email: "browser-owner@example.com", Password: "Offline-Browser-Password123!"}))
	require.NoError(t, err)
	agentReq := connect.NewRequest(&identitypb.CreateAgentRequest{Name: "Example product engineer"})
	agentReq.Header().Set("Authorization", "Bearer "+signed.Msg.AccessToken)
	agent, err := client.CreateAgent(context.Background(), agentReq)
	require.NoError(t, err)

	second, err := client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{Email: "browser-totp@example.com", Password: "Offline-Browser-Password123!"}))
	require.NoError(t, err)
	setupReq := connect.NewRequest(&identitypb.BeginTotpSetupRequest{})
	setupReq.Header().Set("Authorization", "Bearer "+second.Msg.AccessToken)
	setup, err := client.BeginTotpSetup(context.Background(), setupReq)
	require.NoError(t, err)
	code, err := totp.GenerateCode(setup.Msg.Secret, time.Now())
	require.NoError(t, err)
	verifyReq := connect.NewRequest(&identitypb.VerifyTotpSetupRequest{Code: code})
	verifyReq.Header().Set("Authorization", "Bearer "+second.Msg.AccessToken)
	_, err = client.VerifyTotpSetup(context.Background(), verifyReq)
	require.NoError(t, err)
	mux.HandleFunc("GET /fixture/recovery", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(struct {
			Code string `json:"code"`
		}{setup.Msg.RecoveryCodes[0]})
	})
	scoped := repo.WithProject(cfg.DefaultProjectID)
	require.NoError(t, scoped.CreateOAuthClient(context.Background(), &service.OAuthClient{ID: "desktop-client", Kind: service.OAuthClientNativePublic, Revision: 1, CreatedAt: 1, UpdatedAt: 1, Registration: service.OAuthClientRegistration{Name: "Example desktop", RedirectURIs: []string{"http://127.0.0.1/callback"}, Resources: []service.OAuthResourceBounds{{Resource: resource, Product: "files", Scopes: []string{"files:read"}}}, GrantTypes: []string{service.OAuthGrantAuthorizationCode, service.OAuthGrantRefreshToken}}}))
	mux.HandleFunc("/fixture/request", func(w http.ResponseWriter, r *http.Request) {
		verifier := strings.Repeat("v", 64)
		challenge := sha256.Sum256([]byte(verifier))
		params := url.Values{"response_type": {"code"}, "client_id": {"desktop-client"}, "redirect_uri": {"http://127.0.0.1:31821/callback"}, "resource": {resource}, "scope": {"files:read"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "state": {"browser-csrf-state"}}
		transport := *server.Client()
		transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, requestErr := transport.Get(server.URL + "/oauth/authorize?" + params.Encode())
		if requestErr != nil {
			http.Error(w, "fixture request failed", http.StatusInternalServerError)
			return
		}
		defer func() { _ = response.Body.Close() }()
		destination, parseErr := url.Parse(response.Header.Get("Location"))
		if parseErr != nil || response.StatusCode != 302 {
			http.Error(w, "fixture authorization failed", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			URL      string `json:"url"`
			Agent    string `json:"agent"`
			Verifier string `json:"verifier"`
		}{server.URL + destination.RequestURI(), agent.Msg.Agent.Id, verifier})
	})
	done := make(chan struct{})
	mux.HandleFunc("POST /fixture/stop", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204); close(done) })
	fmt.Println("BROWSER_FIXTURE_URL=" + server.URL)
	select {
	case <-done:
	case <-time.After(3 * time.Minute):
		t.Fatal("browser fixture timed out")
	}
}

type browserAssuranceVerifier struct{}

func (browserAssuranceVerifier) Name() string { return assurance.ProviderTurnstile }
func (browserAssuranceVerifier) Verify(_ context.Context, token, _ string) error {
	if token != "offline-browser-captcha-proof" {
		return assurance.ErrVerificationFailed
	}
	return nil
}
