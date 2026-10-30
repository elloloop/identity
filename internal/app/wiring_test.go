package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/oauth"
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
	// Enabled → a real verifier even with no env audiences: audiences are now
	// resolved per-request from the project scope (config_json), so a deployment
	// that configures native audiences only per-project still gets a verifier.
	if v := buildNativeOAuthVerifier(&config.Config{NativeOAuthEnabled: true}, zap.NewNop()); v == nil {
		t.Fatal("enabled native oauth should yield a verifier")
	}
	// Enabled + env audiences → a real verifier (default-project seed logged).
	cfg := &config.Config{
		NativeOAuthEnabled:            true,
		NativeOAuthGoogleAudiences:    "web-client",
		NativeOAuthAppleAudiences:     "dev.acme.example",
		NativeOAuthMicrosoftAudiences: "ms-client",
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

// A disabled OIDC block is ignored, even when its provider key names a
// built-in provider (the reserved-key check runs only when OIDC is enabled):
// the built-in keeps its own env client.
func TestBuildOAuthRegistry_DisabledOIDCKeepsBuiltIns(t *testing.T) {
	cfg := &config.Config{
		GoogleClientID:   "env-google",
		OIDCProviderKey:  "google",
		OIDCIssuer:       "https://acme.example",
		OIDCClientID:     "leftover-oidc",
		OIDCClientSecret: "leftover-oidc-secret",
	}
	cfg.GoogleClientSecret = testCredential("google")
	for name, e := range map[string]func() (oauth.Exchanger, bool){
		"registry": func() (oauth.Exchanger, bool) { return buildOAuthRegistry(cfg, zap.NewNop()).Get("google") },
		"builder":  func() (oauth.Exchanger, bool) { return envOAuthProviderBuilder(cfg)("google", "env-google", "s") },
	} {
		exchanger, ok := e()
		if !ok {
			t.Fatalf("%s: google not built", name)
		}
		u, err := exchanger.(oauth.Authorizer).AuthorizationURL(context.Background(), "https://auth.a.example/cb", "state", "challenge")
		if err != nil {
			t.Fatalf("%s: AuthorizationURL: %v", name, err)
		}
		if !strings.Contains(u, "client_id=env-google") || !strings.Contains(u, "accounts.google.com") {
			t.Fatalf("%s: google authorization url %q is not the env Google client", name, u)
		}
	}
	if n := buildOAuthRegistry(cfg, zap.NewNop()).Len(); n != 1 {
		t.Fatalf("registry Len = %d, want 1 (google only)", n)
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

// The env provider builder rebuilds an env provider with another client: the
// client changes, every other env setting (endpoints, the Microsoft tenant,
// Apple's signing identity) is kept, and a provider the env does not
// configure is not built at all.
func TestEnvOAuthProviderBuilder(t *testing.T) {
	cfg := &config.Config{
		GoogleClientID:         "env-google",
		GoogleAuthorizationURL: "https://accounts.example/authorize",
		MicrosoftClientID:      "env-microsoft",
		MicrosoftTenantID:      "acme-tenant",
		AppleClientID:          "example.env.web",
		AppleTeamID:            "team",
		AppleKeyID:             "key",
		OIDCEnabled:            true,
		OIDCProviderKey:        "OIDC",
		OIDCIssuer:             "https://acme.example",
		OIDCClientID:           "env-oidc",
		OIDCClientSecret:       "env-oidc-secret",
	}
	cfg.GoogleClientSecret = testCredential("google")
	cfg.MicrosoftClientSecret = testCredential("microsoft")
	cfg.ApplePrivateKey = testCredential("apple")

	build := envOAuthProviderBuilder(cfg)
	authURL := func(t *testing.T, provider, clientID string) string {
		t.Helper()
		e, ok := build(provider, clientID, "override-secret")
		if !ok {
			t.Fatalf("%s: env provider not built", provider)
		}
		a, ok := e.(oauth.Authorizer)
		if !ok {
			t.Fatalf("%s: exchanger is not an Authorizer", provider)
		}
		u, err := a.AuthorizationURL(context.Background(), "https://auth.b.example/oauth/callback/"+provider, "state", "challenge")
		if err != nil {
			t.Fatalf("%s: AuthorizationURL: %v", provider, err)
		}
		return u
	}

	for _, tc := range []struct{ provider, clientID, keeps string }{
		{"google", "override-google", "https://accounts.example/authorize?"},
		{"microsoft", "override-microsoft", "/acme-tenant/"},
		{"apple", "example.override.web", "https://appleid.apple.com/"},
	} {
		u := authURL(t, tc.provider, tc.clientID)
		if !strings.Contains(u, "client_id="+url.QueryEscape(tc.clientID)) {
			t.Errorf("%s: authorization url %q does not carry the override client", tc.provider, u)
		}
		if !strings.Contains(u, tc.keeps) {
			t.Errorf("%s: authorization url %q lost the env setting %q", tc.provider, u, tc.keeps)
		}
	}

	// A host client can name the env OIDC provider only under the built-in
	// "oidc" key (ADR-0019), which is the one it rebuilds under.
	if _, ok := build("oidc", "override-oidc", "s"); !ok {
		t.Error("the env OIDC provider must rebuild under its normalized key")
	}
	for _, provider := range []string{"github", "OIDC", "unknown"} {
		if _, ok := build(provider, "c", "s"); ok {
			t.Errorf("%s: a provider the env does not configure must not be built", provider)
		}
	}
}
