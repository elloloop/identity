package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

func testCredential(provider string) string {
	return provider + "-configured"
}

func TestBuildOAuthRegistry(t *testing.T) {
	empty := buildOAuthRegistry(&config.Config{}, nil)
	if empty == nil {
		t.Fatal("empty registry is nil")
	}
	if empty.Len() != 0 {
		t.Fatalf("empty registry Len = %d", empty.Len())
	}

	cfg := &config.Config{
		GoogleClientID:    "google-client",
		MicrosoftClientID: "microsoft-client",
		MicrosoftTenantID: "common",
		GitHubClientID:    "github-client",
		AppleClientID:     "apple-client",
	}
	cfg.GoogleClientSecret = testCredential("google")
	cfg.MicrosoftClientSecret = testCredential("microsoft")
	cfg.GitHubClientSecret = testCredential("github")
	cfg.ApplePrivateKey = testCredential("apple")
	cfg.AppleTeamID = "team"
	cfg.AppleKeyID = "key"

	registry := buildOAuthRegistry(cfg, zap.NewNop())
	if registry.Len() != 4 {
		t.Fatalf("registry Len = %d", registry.Len())
	}
	got := make(map[string]bool)
	for _, provider := range registry.Providers() {
		got[provider] = true
	}
	for _, provider := range []string{"google", "microsoft", "github", "apple"} {
		if !got[provider] {
			t.Fatalf("provider %q not registered; got %v", provider, registry.Providers())
		}
	}
}

func TestBuildNativeOAuthVerifier(t *testing.T) {
	// Disabled → nil verifier (RPC stays off).
	if v := buildNativeOAuthVerifier(&config.Config{}, nil); v != nil {
		t.Fatal("disabled native oauth should yield a nil verifier")
	}
	// Enabled flag but no audiences → still nil (nothing could verify).
	if v := buildNativeOAuthVerifier(&config.Config{NativeOAuthEnabled: true}, zap.NewNop()); v != nil {
		t.Fatal("native oauth without audiences should yield a nil verifier")
	}
	// Enabled + audiences → a real verifier.
	cfg := &config.Config{
		NativeOAuthEnabled:         true,
		NativeOAuthGoogleAudiences: "web-client",
		NativeOAuthAppleAudiences:  "dev.easyloops.app",
	}
	if v := buildNativeOAuthVerifier(cfg, zap.NewNop()); v == nil {
		t.Fatal("enabled native oauth with audiences should yield a verifier")
	}
}

// TestBuildOAuthRegistry_GenericOIDCKeyNormalized guards the blocker: a
// mixed-case / whitespace provider key must be registered under the same
// lowercased/trimmed key the service uses for lookups, so login resolves.
func TestBuildOAuthRegistry_GenericOIDCKeyNormalized(t *testing.T) {
	cfg := &config.Config{
		OIDCEnabled:      true,
		OIDCProviderKey:  "  Okta  ",
		OIDCIssuer:       "https://acme.okta.com",
		OIDCClientID:     "okta-client",
		OIDCClientSecret: "okta-secret",
	}
	registry := buildOAuthRegistry(cfg, zap.NewNop())
	if _, ok := registry.Get("okta"); !ok {
		t.Fatalf("generic OIDC provider not registered under normalized key %q; got %v",
			"okta", registry.Providers())
	}
	if _, ok := registry.Get("  Okta  "); ok {
		t.Fatal("provider registered under the raw un-normalized key")
	}
}

func TestBuildEmailTransport(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{"log only", &config.Config{}},
		{"bad json providers", &config.Config{SMTPProviders: "not-json"}},
		{"invalid json provider", &config.Config{SMTPProviders: `[{"Host":"","Port":2525}]`}},
		{"valid json provider", &config.Config{SMTPProviders: `[{"Host":"smtp.example.com","Port":2525,"From":"noreply@example.com"}]`}},
		{"invalid single provider", &config.Config{SMTPHost: "smtp.example.com", SMTPPort: -1}},
		{"valid single starttls provider", &config.Config{SMTPHost: "smtp.example.com", SMTPPort: 587, SMTPFrom: "noreply@example.com", SMTPTLS: true}},
		{"valid single tls provider", &config.Config{SMTPHost: "smtp.example.com", SMTPPort: 465, SMTPFrom: "noreply@example.com", SMTPTLS: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if transport := buildEmailTransport(tc.cfg, nil); transport == nil {
				t.Fatal("transport is nil")
			}
		})
	}
}

func TestNewBuildsHealthHandler(t *testing.T) {
	signer := jwttest.NewSigner(t, "app-test")
	passkeyService, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   "localhost",
		RPName: "Identity Test",
		Origin: "http://localhost:9002",
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()
	built, err := New(Deps{
		Config: &config.Config{ // #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
			DefaultTenantID:               "tenant",
			AuthAllowLocal:                true,
			PasswordSignupEnabled:         true,
			PasswordResetEnabled:          true,
			AllowedOrigins:                "http://localhost:9002",
			JWTExpirySeconds:              900,
			RefreshExpirySeconds:          604800,
			LoginMaxFailedAttempts:        5,
			LoginLockoutSeconds:           900,
			LoginChallengeExpirySeconds:   300,
			PasskeyRPID:                   "localhost",
			PasskeyRPName:                 "Identity Test",
			PasskeyOrigin:                 "http://localhost:9002",
			PasskeyChallengeExpirySeconds: 300,
			QRLoginBaseURL:                "http://localhost:9002",
			QRLoginExpirySeconds:          300,
			TOTPIssuer:                    "Identity Test",
			PasswordResetExpirySeconds:    3600,
		},
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               repo,
		DB:                 repo,
		Passkeys:           passkeyService,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built.Start()
	handler := built.Handler
	t.Cleanup(built.Stop)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("health status = %d body=%q", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != `{"status":"ok"}` {
		t.Fatalf("health body = %q", rr.Body.String())
	}
}
