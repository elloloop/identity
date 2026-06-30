package config

import (
	"os"
	"testing"
	"time"
)

// TestLoad_Defaults verifies that Load returns sensible defaults when
// no environment variables are set.
func TestLoad_Defaults(t *testing.T) {
	// Clear all GATEWAY_ env vars that might interfere.
	clearGatewayEnv(t)

	cfg := Load()

	if cfg.GRPCPort != 50051 {
		t.Errorf("GRPCPort: want 50051, got %d", cfg.GRPCPort)
	}
	if cfg.ConnectPort != 80 {
		t.Errorf("ConnectPort: want 80, got %d", cfg.ConnectPort)
	}
	if cfg.MetricsPort != 9090 {
		t.Errorf("MetricsPort: want 9090, got %d", cfg.MetricsPort)
	}
	if cfg.RepoDriver != "postgres" {
		t.Errorf("RepoDriver: want postgres, got %q", cfg.RepoDriver)
	}
	if cfg.DefaultTenantID != "local" {
		t.Errorf("DefaultTenantID: want local, got %q", cfg.DefaultTenantID)
	}
	if cfg.DefaultProjectID != "default" {
		t.Errorf("DefaultProjectID: want default, got %q", cfg.DefaultProjectID)
	}
	if cfg.AdminAPISecret != "" {
		t.Errorf("AdminAPISecret: want empty default (admin RPCs disabled), got %q", cfg.AdminAPISecret)
	}
	if cfg.PublicEmailDomains != "" {
		t.Errorf("PublicEmailDomains: want empty default, got %q", cfg.PublicEmailDomains)
	}
	if cfg.JWTExpirySeconds != 900 {
		t.Errorf("JWTExpirySeconds: want 900, got %d", cfg.JWTExpirySeconds)
	}
	if cfg.ProjectResolutionCacheTTLSeconds != 30 {
		t.Errorf("ProjectResolutionCacheTTLSeconds: want 30, got %d", cfg.ProjectResolutionCacheTTLSeconds)
	}
	if cfg.ProjectResolutionCacheTTL() != 30*time.Second {
		t.Errorf("ProjectResolutionCacheTTL: want 30s, got %s", cfg.ProjectResolutionCacheTTL())
	}
	if cfg.ProjectResolutionCacheMaxEntries != 10000 {
		t.Errorf("ProjectResolutionCacheMaxEntries: want 10000, got %d", cfg.ProjectResolutionCacheMaxEntries)
	}
	if cfg.PasswordSignupEnabled != true {
		t.Errorf("PasswordSignupEnabled: want true, got %v", cfg.PasswordSignupEnabled)
	}
	if cfg.PasswordResetEnabled != true {
		t.Errorf("PasswordResetEnabled: want true, got %v", cfg.PasswordResetEnabled)
	}
	if cfg.RefreshExpirySeconds != 604800 {
		t.Errorf("RefreshExpirySeconds: want 604800, got %d", cfg.RefreshExpirySeconds)
	}
	if cfg.LoginMaxFailedAttempts != 5 {
		t.Errorf("LoginMaxFailedAttempts: want 5, got %d", cfg.LoginMaxFailedAttempts)
	}
	if cfg.LoginLockoutSeconds != 900 {
		t.Errorf("LoginLockoutSeconds: want 900, got %d", cfg.LoginLockoutSeconds)
	}
	if cfg.AuthAllowLocal != true {
		t.Errorf("AuthAllowLocal: want true, got %v", cfg.AuthAllowLocal)
	}
	if cfg.DefaultEmailDomain != "glassa.work" {
		t.Errorf("DefaultEmailDomain: want glassa.work, got %q", cfg.DefaultEmailDomain)
	}
	if cfg.TOTPIssuer != "Glassa Work" {
		t.Errorf("TOTPIssuer: want 'Glassa Work', got %q", cfg.TOTPIssuer)
	}
	if cfg.PasskeyRPID != "localhost" {
		t.Errorf("PasskeyRPID: want localhost, got %q", cfg.PasskeyRPID)
	}
	if cfg.CookieSameSite != "Lax" {
		t.Errorf("CookieSameSite: want Lax, got %q", cfg.CookieSameSite)
	}
	if cfg.PostgresMaxConns != 25 {
		t.Errorf("PostgresMaxConns: want 25, got %d", cfg.PostgresMaxConns)
	}
	if cfg.PostgresConnTimeoutMs != DefaultPostgresConnTimeoutMs {
		t.Errorf("PostgresConnTimeoutMs: want %d, got %d", DefaultPostgresConnTimeoutMs, cfg.PostgresConnTimeoutMs)
	}
	if cfg.SweeperIntervalSeconds != 300 {
		t.Errorf("SweeperIntervalSeconds: want 300, got %d", cfg.SweeperIntervalSeconds)
	}
	if cfg.SweeperBatchSize != 500 {
		t.Errorf("SweeperBatchSize: want 500, got %d", cfg.SweeperBatchSize)
	}
	if cfg.SweeperGraceSeconds != 60 {
		t.Errorf("SweeperGraceSeconds: want 60, got %d", cfg.SweeperGraceSeconds)
	}
	if cfg.AppleClientID != "" {
		t.Errorf("AppleClientID: want empty default, got %q", cfg.AppleClientID)
	}
	if cfg.AppleTeamID != "" {
		t.Errorf("AppleTeamID: want empty default, got %q", cfg.AppleTeamID)
	}
	if cfg.AppleKeyID != "" {
		t.Errorf("AppleKeyID: want empty default, got %q", cfg.AppleKeyID)
	}
	if cfg.ApplePrivateKey != "" {
		t.Errorf("ApplePrivateKey: want empty default, got %q", cfg.ApplePrivateKey)
	}
}

// TestLoad_SweeperDisabledWhenIntervalZero asserts the documented
// behaviour: setting GATEWAY_SWEEPER_INTERVAL_SECONDS=0 in the
// environment loads as 0 (which app.New uses to skip starting the
// sweeper goroutine).
func TestLoad_SweeperDisabledWhenIntervalZero(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_SWEEPER_INTERVAL_SECONDS", "0")

	cfg := Load()
	if cfg.SweeperIntervalSeconds != 0 {
		t.Errorf("SweeperIntervalSeconds: want 0, got %d", cfg.SweeperIntervalSeconds)
	}
}

// TestLoad_OverrideFromEnv verifies that environment variables override defaults.
func TestLoad_OverrideFromEnv(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_GRPC_PORT", "9999")
	t.Setenv("GATEWAY_REPO_DRIVER", "memory")
	t.Setenv("GATEWAY_DEFAULT_TENANT_ID", "prod-tenant")
	t.Setenv("GATEWAY_DEFAULT_PROJECT_ID", "prod-project")
	t.Setenv("GATEWAY_ADMIN_API_SECRET", "operator-secret")
	t.Setenv("GATEWAY_JWT_EXPIRY_SECONDS", "1800")
	t.Setenv("GATEWAY_AUTH_ALLOW_LOCAL", "false")
	t.Setenv("GATEWAY_PASSWORD_SIGNUP_ENABLED", "false")
	t.Setenv("GATEWAY_PASSWORD_RESET_ENABLED", "false")
	t.Setenv("GATEWAY_LOGIN_MAX_FAILED_ATTEMPTS", "10")
	t.Setenv("GATEWAY_POSTGRES_CONN_TIMEOUT_MS", "2500")
	t.Setenv("GATEWAY_TOTP_ISSUER", "My Corp")
	t.Setenv("GATEWAY_OAUTH_APPLE_CLIENT_ID", "apple-client")
	t.Setenv("GATEWAY_OAUTH_APPLE_TEAM_ID", "apple-team")
	t.Setenv("GATEWAY_OAUTH_APPLE_KEY_ID", "apple-key")
	t.Setenv("GATEWAY_OAUTH_APPLE_PRIVATE_KEY", "apple-private")

	cfg := Load()

	if cfg.GRPCPort != 9999 {
		t.Errorf("GRPCPort: want 9999, got %d", cfg.GRPCPort)
	}
	if cfg.RepoDriver != "memory" {
		t.Errorf("RepoDriver: want memory, got %q", cfg.RepoDriver)
	}
	if cfg.DefaultTenantID != "prod-tenant" {
		t.Errorf("DefaultTenantID: want prod-tenant, got %q", cfg.DefaultTenantID)
	}
	if cfg.DefaultProjectID != "prod-project" {
		t.Errorf("DefaultProjectID: want prod-project, got %q", cfg.DefaultProjectID)
	}
	if cfg.AdminAPISecret != "operator-secret" {
		t.Errorf("AdminAPISecret: want operator-secret, got %q", cfg.AdminAPISecret)
	}
	if cfg.JWTExpirySeconds != 1800 {
		t.Errorf("JWTExpirySeconds: want 1800, got %d", cfg.JWTExpirySeconds)
	}
	if cfg.AuthAllowLocal != false {
		t.Errorf("AuthAllowLocal: want false, got %v", cfg.AuthAllowLocal)
	}
	if cfg.PasswordSignupEnabled != false {
		t.Errorf("PasswordSignupEnabled: want false, got %v", cfg.PasswordSignupEnabled)
	}
	if cfg.PasswordResetEnabled != false {
		t.Errorf("PasswordResetEnabled: want false, got %v", cfg.PasswordResetEnabled)
	}
	if cfg.LoginMaxFailedAttempts != 10 {
		t.Errorf("LoginMaxFailedAttempts: want 10, got %d", cfg.LoginMaxFailedAttempts)
	}
	if cfg.PostgresConnTimeoutMs != 2500 {
		t.Errorf("PostgresConnTimeoutMs: want 2500, got %d", cfg.PostgresConnTimeoutMs)
	}
	if cfg.TOTPIssuer != "My Corp" {
		t.Errorf("TOTPIssuer: want 'My Corp', got %q", cfg.TOTPIssuer)
	}
	if cfg.AppleClientID != "apple-client" {
		t.Errorf("AppleClientID: want apple-client, got %q", cfg.AppleClientID)
	}
	if cfg.AppleTeamID != "apple-team" {
		t.Errorf("AppleTeamID: want apple-team, got %q", cfg.AppleTeamID)
	}
	if cfg.AppleKeyID != "apple-key" {
		t.Errorf("AppleKeyID: want apple-key, got %q", cfg.AppleKeyID)
	}
	if cfg.ApplePrivateKey != "apple-private" {
		t.Errorf("ApplePrivateKey: want apple-private, got %q", cfg.ApplePrivateKey)
	}
}

func TestLoad_GenericOIDC_Defaults(t *testing.T) {
	clearGatewayEnv(t)
	cfg := Load()
	if cfg.OIDCEnabled {
		t.Errorf("OIDCEnabled should default to false")
	}
	if cfg.OIDCProviderKey != "" || cfg.OIDCIssuer != "" || cfg.OIDCClientID != "" ||
		cfg.OIDCClientSecret != "" || cfg.OIDCScopes != "" || cfg.OIDCDiscoveryURL != "" {
		t.Errorf("generic OIDC fields should default empty: %+v", cfg)
	}
	if got := cfg.OIDCScopeList(); got != nil {
		t.Errorf("OIDCScopeList default should be nil, got %v", got)
	}
}

func TestLoad_GenericOIDC_Overrides(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_OAUTH_OIDC_ENABLED", "true")
	t.Setenv("GATEWAY_OAUTH_OIDC_PROVIDER_KEY", "okta")
	t.Setenv("GATEWAY_OAUTH_OIDC_ISSUER", "https://acme.okta.com")
	t.Setenv("GATEWAY_OAUTH_OIDC_DISCOVERY_URL", "https://acme.okta.com/.well-known/openid-configuration")
	t.Setenv("GATEWAY_OAUTH_OIDC_CLIENT_ID", "okta-client")
	t.Setenv("GATEWAY_OAUTH_OIDC_CLIENT_SECRET", "okta-secret")
	t.Setenv("GATEWAY_OAUTH_OIDC_SCOPES", "openid email groups")

	cfg := Load()

	if !cfg.OIDCEnabled || cfg.OIDCProviderKey != "okta" ||
		cfg.OIDCIssuer != "https://acme.okta.com" ||
		cfg.OIDCDiscoveryURL != "https://acme.okta.com/.well-known/openid-configuration" ||
		cfg.OIDCClientID != "okta-client" || cfg.OIDCClientSecret != "okta-secret" {
		t.Errorf("generic OIDC config not loaded: %+v", cfg)
	}
	scopes := cfg.OIDCScopeList()
	if len(scopes) != 3 || scopes[2] != "groups" {
		t.Errorf("OIDCScopeList wrong: %v", scopes)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid generic OIDC config should pass Validate: %v", err)
	}
}

func TestValidate_GenericOIDC_Invariants(t *testing.T) {
	base := func() *Config {
		return &Config{
			OIDCEnabled:      true,
			OIDCProviderKey:  "okta",
			OIDCIssuer:       "https://acme.okta.com",
			OIDCClientID:     "okta-client",
			OIDCClientSecret: "okta-secret",
		}
	}
	t.Run("missing key", func(t *testing.T) {
		c := base()
		c.OIDCProviderKey = ""
		if err := c.validateOIDC(); err == nil {
			t.Error("want error for missing provider key")
		}
	})
	t.Run("reserved key", func(t *testing.T) {
		c := base()
		c.OIDCProviderKey = "google"
		if err := c.validateOIDC(); err == nil {
			t.Error("want error for reserved provider key")
		}
	})
	t.Run("missing issuer and discovery", func(t *testing.T) {
		c := base()
		c.OIDCIssuer = ""
		c.OIDCDiscoveryURL = ""
		if err := c.validateOIDC(); err == nil {
			t.Error("want error when both issuer and discovery url are empty")
		}
	})
	t.Run("discovery url substitutes for issuer", func(t *testing.T) {
		c := base()
		c.OIDCIssuer = ""
		c.OIDCDiscoveryURL = "https://acme.okta.com/.well-known/openid-configuration"
		if err := c.validateOIDC(); err != nil {
			t.Errorf("discovery url should satisfy the issuer requirement: %v", err)
		}
	})
	t.Run("missing credentials", func(t *testing.T) {
		c := base()
		c.OIDCClientSecret = ""
		if err := c.validateOIDC(); err == nil {
			t.Error("want error for missing client secret")
		}
	})
	t.Run("disabled skips all checks", func(t *testing.T) {
		c := &Config{OIDCEnabled: false}
		if err := c.validateOIDC(); err != nil {
			t.Errorf("disabled OIDC should never error: %v", err)
		}
	})
}

// TestEnvStr_Default verifies envStr returns the default for unset vars.
func TestEnvStr_Default(t *testing.T) {
	clearGatewayEnv(t)
	got := envStr("GATEWAY_TEST_UNSET_STR", "fallback")
	if got != "fallback" {
		t.Errorf("want fallback, got %q", got)
	}
}

// TestEnvStr_Override verifies envStr reads the environment.
func TestEnvStr_Override(t *testing.T) {
	t.Setenv("GATEWAY_TEST_STR_OVERRIDE", "custom-value")
	got := envStr("GATEWAY_TEST_STR_OVERRIDE", "default")
	if got != "custom-value" {
		t.Errorf("want custom-value, got %q", got)
	}
}

// TestEnvInt_Default verifies envInt returns the default for unset vars.
func TestEnvInt_Default(t *testing.T) {
	clearGatewayEnv(t)
	got := envInt("GATEWAY_TEST_UNSET_INT", 42)
	if got != 42 {
		t.Errorf("want 42, got %d", got)
	}
}

// TestEnvInt_Override verifies envInt reads the environment.
func TestEnvInt_Override(t *testing.T) {
	t.Setenv("GATEWAY_TEST_INT_OVERRIDE", "8080")
	got := envInt("GATEWAY_TEST_INT_OVERRIDE", 3000)
	if got != 8080 {
		t.Errorf("want 8080, got %d", got)
	}
}

// TestEnvInt_InvalidFallsBackToDefault verifies that a non-integer
// env value falls back to the default.
func TestEnvInt_InvalidFallsBackToDefault(t *testing.T) {
	t.Setenv("GATEWAY_TEST_INT_BAD", "not-a-number")
	got := envInt("GATEWAY_TEST_INT_BAD", 99)
	if got != 99 {
		t.Errorf("want 99 (default), got %d", got)
	}
}

// TestEnvBool_Variants verifies all recognized boolean representations.
func TestEnvBool_Variants(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"1", true},
		{"yes", true},
		{"Yes", true},
		{"YES", true},
		{"false", false},
		{"False", false},
		{"FALSE", false},
		{"0", false},
		{"no", false},
		{"No", false},
		{"NO", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Setenv("GATEWAY_TEST_BOOL_VAR", tt.input)
			got := envBool("GATEWAY_TEST_BOOL_VAR", !tt.want)
			if got != tt.want {
				t.Errorf("envBool(%q): want %v, got %v", tt.input, tt.want, got)
			}
		})
	}
}

// TestEnvFloat_Default verifies envFloat returns the default for unset vars.
func TestEnvFloat_Default(t *testing.T) {
	clearGatewayEnv(t)
	got := envFloat("GATEWAY_TEST_UNSET_FLOAT", 0.5)
	if got != 0.5 {
		t.Errorf("want 0.5, got %v", got)
	}
}

// TestEnvFloat_Override verifies envFloat reads the environment.
func TestEnvFloat_Override(t *testing.T) {
	t.Setenv("GATEWAY_TEST_FLOAT_OVERRIDE", "0.25")
	got := envFloat("GATEWAY_TEST_FLOAT_OVERRIDE", 0.1)
	if got != 0.25 {
		t.Errorf("want 0.25, got %v", got)
	}
}

// TestEnvFloat_InvalidFallsBackToDefault verifies that a non-float
// env value falls back to the default.
func TestEnvFloat_InvalidFallsBackToDefault(t *testing.T) {
	t.Setenv("GATEWAY_TEST_FLOAT_BAD", "not-a-float")
	got := envFloat("GATEWAY_TEST_FLOAT_BAD", 0.7)
	if got != 0.7 {
		t.Errorf("want 0.7, got %v", got)
	}
}

// TestEnvBool_UnrecognizedFallsBackToDefault verifies that an
// unrecognized string falls back to the default.
func TestEnvBool_UnrecognizedFallsBackToDefault(t *testing.T) {
	t.Setenv("GATEWAY_TEST_BOOL_BAD", "maybe")
	got := envBool("GATEWAY_TEST_BOOL_BAD", true)
	if got != true {
		t.Errorf("want true (default), got %v", got)
	}
	got = envBool("GATEWAY_TEST_BOOL_BAD", false)
	if got != false {
		t.Errorf("want false (default), got %v", got)
	}
}

// TestJWTExpiry verifies the duration helper.
func TestJWTExpiry(t *testing.T) {
	cfg := &Config{JWTExpirySeconds: 900}
	if cfg.JWTExpiry() != 15*time.Minute {
		t.Errorf("want 15m, got %v", cfg.JWTExpiry())
	}
}

// TestRefreshExpiry verifies the refresh duration helper.
func TestRefreshExpiry(t *testing.T) {
	cfg := &Config{RefreshExpirySeconds: 604800}
	if cfg.RefreshExpiry() != 7*24*time.Hour {
		t.Errorf("want 7d, got %v", cfg.RefreshExpiry())
	}
}

// TestEmailServiceAddress verifies the address helper.
func TestEmailServiceAddress(t *testing.T) {
	cfg := &Config{EmailServiceHost: "mail.internal", EmailServicePort: 50053}
	want := "mail.internal:50053"
	if got := cfg.EmailServiceAddress(); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// clearGatewayEnv unsets all GATEWAY_ environment variables to ensure
// test isolation. Uses t.Setenv-style cleanup so the original
// environment is restored after the test.
func clearGatewayEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		key := kv[:findByte(kv, '=')]
		if len(key) > 8 && key[:8] == "GATEWAY_" {
			t.Setenv(key, "")
			_ = os.Unsetenv(key)
		}
	}
}

func findByte(s string, b byte) int {
	for i := range len(s) {
		if s[i] == b {
			return i
		}
	}
	return len(s)
}

// TestLoad_GoogleOIDCEndpointOverrides verifies the Google OIDC endpoint
// overrides flow from env into config — they let a self-hosted gateway (or an
// end-to-end test against a mock OIDC provider) point the Google provider at
// non-default endpoints. Empty defaults (the real Google) are covered by the
// all-defaults test.
func TestLoad_GoogleOIDCEndpointOverrides(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_OAUTH_GOOGLE_DISCOVERY_URL", "http://mock/.well-known/openid-configuration")
	t.Setenv("GATEWAY_OAUTH_GOOGLE_AUTHORIZATION_URL", "http://mock/authorize")
	t.Setenv("GATEWAY_OAUTH_GOOGLE_TOKEN_URL", "http://mock/token")
	t.Setenv("GATEWAY_OAUTH_GOOGLE_JWKS_URL", "http://mock/jwks")
	t.Setenv("GATEWAY_OAUTH_GOOGLE_USERINFO_URL", "http://mock/userinfo")
	t.Setenv("GATEWAY_OAUTH_GOOGLE_ISSUER", "http://mock")

	cfg := Load()

	for _, c := range []struct{ field, got, want string }{
		{"GoogleDiscoveryURL", cfg.GoogleDiscoveryURL, "http://mock/.well-known/openid-configuration"},
		{"GoogleAuthorizationURL", cfg.GoogleAuthorizationURL, "http://mock/authorize"},
		{"GoogleTokenURL", cfg.GoogleTokenURL, "http://mock/token"},
		{"GoogleJWKSURL", cfg.GoogleJWKSURL, "http://mock/jwks"},
		{"GoogleUserinfoURL", cfg.GoogleUserinfoURL, "http://mock/userinfo"},
		{"GoogleIssuer", cfg.GoogleIssuer, "http://mock"},
	} {
		if c.got != c.want {
			t.Errorf("%s: want %q, got %q", c.field, c.want, c.got)
		}
	}
}
