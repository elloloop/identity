package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// ── Comprehensive default tests ────────────────────────────────────────

func TestEnvTest_AllDefaults(t *testing.T) {
	clearGatewayEnv(t)
	cfg := Load()

	checks := []struct {
		field string
		got   interface{}
		want  interface{}
	}{
		{"GRPCPort", cfg.GRPCPort, 50051},
		{"ConnectPort", cfg.ConnectPort, 80},
		{"MetricsPort", cfg.MetricsPort, 9090},
		{"RepoDriver", cfg.RepoDriver, "postgres"},
		{"DefaultTenantID", cfg.DefaultTenantID, "local"},
		{"EmailServiceHost", cfg.EmailServiceHost, "email-service"},
		{"EmailServicePort", cfg.EmailServicePort, 50053},
		{"JWTSigner", cfg.JWTSigner, "file"},
		{"JWTKeysFile", cfg.JWTKeysFile, ""},
		{"JWTKMSKeys", cfg.JWTKMSKeys, ""},
		{"JWTKMSAWSRegion", cfg.JWTKMSAWSRegion, ""},
		{"JWTExpirySeconds", cfg.JWTExpirySeconds, 900},
		{"RefreshExpirySeconds", cfg.RefreshExpirySeconds, 604800},
		{"GoogleClientID", cfg.GoogleClientID, ""},
		{"GoogleClientSecret", cfg.GoogleClientSecret, ""},
		{"GoogleAuthorizationURL", cfg.GoogleAuthorizationURL, ""},
		{"GoogleTokenURL", cfg.GoogleTokenURL, ""},
		{"GoogleJWKSURL", cfg.GoogleJWKSURL, ""},
		{"GoogleDiscoveryURL", cfg.GoogleDiscoveryURL, ""},
		{"GoogleUserinfoURL", cfg.GoogleUserinfoURL, ""},
		{"GoogleIssuer", cfg.GoogleIssuer, ""},
		{"MicrosoftClientID", cfg.MicrosoftClientID, ""},
		{"MicrosoftClientSecret", cfg.MicrosoftClientSecret, ""},
		{"MicrosoftTenantID", cfg.MicrosoftTenantID, ""},
		{"PasswordSignupEnabled", cfg.PasswordSignupEnabled, true},
		{"AccountMergeEnabled", cfg.AccountMergeEnabled, false},
		{"PasswordResetEnabled", cfg.PasswordResetEnabled, true},
		{"PasswordResetExpirySeconds", cfg.PasswordResetExpirySeconds, 900},
		{"PasswordlessSignupEnabled", cfg.PasswordlessSignupEnabled, true},
		{"PasswordlessCodeTTLSeconds", cfg.PasswordlessCodeTTLSeconds, 300},
		{"PasswordlessCodeMaxAttempts", cfg.PasswordlessCodeMaxAttempts, 5},
		{"PasswordlessMagicLinkTTLSeconds", cfg.PasswordlessMagicLinkTTLSeconds, 900},
		{"RateLimitPasswordlessPerIP", cfg.RateLimitPasswordlessPerIP, 5},
		{"TOTPEncryptionKey", cfg.TOTPEncryptionKey, ""},
		{"TOTPIssuer", cfg.TOTPIssuer, "Identity"},
		{"TOTPRecoveryPepper", cfg.TOTPRecoveryPepper, ""},
		{"LoginChallengeExpirySeconds", cfg.LoginChallengeExpirySeconds, 300},
		{"PasskeyRPID", cfg.PasskeyRPID, "localhost"},
		{"PasskeyRPName", cfg.PasskeyRPName, "Identity"},
		{"PasskeyOrigin", cfg.PasskeyOrigin, "http://localhost:9002"},
		{"PasskeyChallengeExpirySeconds", cfg.PasskeyChallengeExpirySeconds, 300},
		{"QRLoginBaseURL", cfg.QRLoginBaseURL, "http://localhost:9002"},
		{"QRLoginExpirySeconds", cfg.QRLoginExpirySeconds, 300},
		{"LoginMaxFailedAttempts", cfg.LoginMaxFailedAttempts, 5},
		{"LoginLockoutSeconds", cfg.LoginLockoutSeconds, 900},
		{"DefaultEmailDomain", cfg.DefaultEmailDomain, ""},
		{"DefaultProjectEmailSignup", cfg.DefaultProjectEmailSignup, ""},
		{"DefaultProjectUsernameSignup", cfg.DefaultProjectUsernameSignup, ""},
		{"AllowedOrigins", cfg.AllowedOrigins, "http://localhost:9002,http://localhost:3000"},
		{"CookieDomain", cfg.CookieDomain, ""},
		{"CookieSecure", cfg.CookieSecure, false},
		{"CookieSameSite", cfg.CookieSameSite, "Lax"},
		{"AuthAllowLocal", cfg.AuthAllowLocal, true},
		{"AuthRequireVerifiedEmail", cfg.AuthRequireVerifiedEmail, true},
		{"SMTPHost", cfg.SMTPHost, ""},
		{"SMTPPort", cfg.SMTPPort, 587},
		{"SMTPUser", cfg.SMTPUser, ""},
		{"SMTPPass", cfg.SMTPPass, ""},
		{"SMTPFrom", cfg.SMTPFrom, ""},
		{"SMTPTLS", cfg.SMTPTLS, true},
		{"SMTPProviders", cfg.SMTPProviders, ""},
		{"AppBaseURL", cfg.AppBaseURL, "http://localhost:9002"},
		{"EmailLinkBaseURL", cfg.EmailLinkBaseURL, ""},
		{"EmailTokenExpirySeconds", cfg.EmailTokenExpirySeconds, 86400},
		{"RevocationMode", cfg.RevocationMode, RevocationModeTTL},
		{"SessionCacheTTLSeconds", cfg.SessionCacheTTLSeconds, 60},
	}

	for _, c := range checks {
		t.Run(c.field, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("%s: got %v, want %v", c.field, c.got, c.want)
			}
		})
	}
}

// ── Per-field override tests ───────────────────────────────────────────

func TestEnvTest_OverrideConnectPort(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_CONNECT_PORT", "8080")
	cfg := Load()
	if cfg.ConnectPort != 8080 {
		t.Errorf("ConnectPort: got %d, want 8080", cfg.ConnectPort)
	}
}

func TestEnvTest_OverrideMetricsPort(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_METRICS_PORT", "9191")
	cfg := Load()
	if cfg.MetricsPort != 9191 {
		t.Errorf("MetricsPort: got %d, want 9191", cfg.MetricsPort)
	}
}

func TestEnvTest_OverrideRefreshExpiry(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_REFRESH_EXPIRY_SECONDS", "86400")
	cfg := Load()
	if cfg.RefreshExpirySeconds != 86400 {
		t.Errorf("RefreshExpirySeconds: got %d, want 86400", cfg.RefreshExpirySeconds)
	}
}

func TestEnvTest_OverridePasswordResetExpiry(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_PASSWORD_RESET_EXPIRY_SECONDS", "7200")
	cfg := Load()
	if cfg.PasswordResetExpirySeconds != 7200 {
		t.Errorf("PasswordResetExpirySeconds: got %d, want 7200", cfg.PasswordResetExpirySeconds)
	}
}

func TestEnvTest_OverridePasswordSignupEnabled(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_PASSWORD_SIGNUP_ENABLED", "false")
	cfg := Load()
	if cfg.PasswordSignupEnabled {
		t.Errorf("PasswordSignupEnabled: got true, want false")
	}
}

func TestEnvTest_OverridePasswordResetEnabled(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_PASSWORD_RESET_ENABLED", "false")
	cfg := Load()
	if cfg.PasswordResetEnabled {
		t.Errorf("PasswordResetEnabled: got true, want false")
	}
}

func TestEnvTest_OverrideGuardianStepUpAllowNoPassword(t *testing.T) {
	clearGatewayEnv(t)
	if cfg := Load(); cfg.GuardianStepUpAllowNoPassword {
		t.Errorf("GuardianStepUpAllowNoPassword: got true, want false by default")
	}
	t.Setenv("GATEWAY_GUARDIAN_STEPUP_ALLOW_NO_PASSWORD", "true")
	if cfg := Load(); !cfg.GuardianStepUpAllowNoPassword {
		t.Errorf("GuardianStepUpAllowNoPassword: got false, want true")
	}
}

func TestEnvTest_OverrideAuthRequireVerifiedEmail(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL", "false")
	cfg := Load()
	if cfg.AuthRequireVerifiedEmail {
		t.Errorf("AuthRequireVerifiedEmail: got true, want false")
	}
}

func TestEnvTest_OverrideCookieSecure(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_COOKIE_SECURE", "true")
	cfg := Load()
	if !cfg.CookieSecure {
		t.Errorf("CookieSecure: got false, want true")
	}
}

func TestEnvTest_OverrideCookieSameSite(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_COOKIE_SAMESITE", "None")
	cfg := Load()
	if cfg.CookieSameSite != "None" {
		t.Errorf("CookieSameSite: got %q, want None", cfg.CookieSameSite)
	}
}

func TestEnvTest_OverrideQRLoginExpiry(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_QR_LOGIN_EXPIRY_SECONDS", "600")
	cfg := Load()
	if cfg.QRLoginExpirySeconds != 600 {
		t.Errorf("QRLoginExpirySeconds: got %d, want 600", cfg.QRLoginExpirySeconds)
	}
}

func TestEnvTest_OverrideSMTPHost(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_SMTP_HOST", "smtp.example.com")
	cfg := Load()
	if cfg.SMTPHost != "smtp.example.com" {
		t.Errorf("SMTPHost: got %q, want smtp.example.com", cfg.SMTPHost)
	}
}

func TestEnvTest_OverrideSMTPPort(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_SMTP_PORT", "465")
	cfg := Load()
	if cfg.SMTPPort != 465 {
		t.Errorf("SMTPPort: got %d, want 465", cfg.SMTPPort)
	}
}

func TestEnvTest_OverrideSMTPTLS(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_SMTP_TLS", "false")
	cfg := Load()
	if cfg.SMTPTLS {
		t.Errorf("SMTPTLS: got true, want false")
	}
}

func TestEnvTest_OverrideAppBaseURL(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_APP_BASE_URL", "https://identity.test")
	cfg := Load()
	if cfg.AppBaseURL != "https://identity.test" {
		t.Errorf("AppBaseURL: got %q, want https://identity.test", cfg.AppBaseURL)
	}
}

func TestEnvTest_OverrideEmailLinkBaseURL(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_EMAIL_LINK_BASE_URL", "https://signin.example.com")
	cfg := Load()
	if cfg.EmailLinkBaseURL != "https://signin.example.com" {
		t.Errorf("EmailLinkBaseURL: got %q, want https://signin.example.com", cfg.EmailLinkBaseURL)
	}
	if err := cfg.validateEmailLinkBaseURL(); err != nil {
		t.Errorf("a loaded https base must validate: %v", err)
	}
}

func TestEnvTest_OverrideEmailTokenExpiry(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_EMAIL_TOKEN_EXPIRY_SECONDS", "7200")
	cfg := Load()
	if cfg.EmailTokenExpirySeconds != 7200 {
		t.Errorf("EmailTokenExpirySeconds: got %d, want 7200", cfg.EmailTokenExpirySeconds)
	}
}

func TestEnvTest_OverrideSMTPProviders(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_SMTP_PROVIDERS", `[{"Host":"a","Port":25}]`)
	cfg := Load()
	if cfg.SMTPProviders == "" {
		t.Errorf("SMTPProviders: got empty, want non-empty")
	}
}

// ── Invalid int env falls back to default ──────────────────────────────

func TestEnvTest_InvalidIntFallback(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_GRPC_PORT", "not_a_number")
	cfg := Load()
	if cfg.GRPCPort != 50051 {
		t.Errorf("GRPCPort with invalid env: got %d, want 50051 (default)", cfg.GRPCPort)
	}
}

func TestEnvTest_EmptyIntFallback(t *testing.T) {
	clearGatewayEnv(t)
	t.Setenv("GATEWAY_GRPC_PORT", "")
	_ = os.Unsetenv("GATEWAY_GRPC_PORT")
	cfg := Load()
	if cfg.GRPCPort != 50051 {
		t.Errorf("GRPCPort with empty env: got %d, want 50051 (default)", cfg.GRPCPort)
	}
}

// ── Bool variants ──────────────────────────────────────────────────────

func TestEnvTest_BoolVariants_True(t *testing.T) {
	for _, v := range []string{"true", "1", "yes", "TRUE", "True", "YES", "Yes"} {
		t.Run("true="+v, func(t *testing.T) {
			clearGatewayEnv(t)
			t.Setenv("GATEWAY_COOKIE_SECURE", v)
			cfg := Load()
			if !cfg.CookieSecure {
				t.Errorf("CookieSecure with %q: got false, want true", v)
			}
		})
	}
}

func TestEnvTest_BoolVariants_False(t *testing.T) {
	for _, v := range []string{"false", "0", "no", "FALSE", "False", "NO", "No"} {
		t.Run("false="+v, func(t *testing.T) {
			clearGatewayEnv(t)
			t.Setenv("GATEWAY_AUTH_ALLOW_LOCAL", v)
			cfg := Load()
			if cfg.AuthAllowLocal {
				t.Errorf("AuthAllowLocal with %q: got true, want false", v)
			}
		})
	}
}

// ── Helper methods ─────────────────────────────────────────────────────

func TestEnvTest_JWTExpiry(t *testing.T) {
	cfg := &Config{JWTExpirySeconds: 1800}
	if cfg.JWTExpiry() != 30*time.Minute {
		t.Errorf("JWTExpiry: got %v, want 30m", cfg.JWTExpiry())
	}
}

func TestEnvTest_RefreshExpiry(t *testing.T) {
	cfg := &Config{RefreshExpirySeconds: 86400}
	if cfg.RefreshExpiry() != 24*time.Hour {
		t.Errorf("RefreshExpiry: got %v, want 24h", cfg.RefreshExpiry())
	}
}

func TestEnvTest_PasswordResetExpiry(t *testing.T) {
	cfg := &Config{PasswordResetExpirySeconds: 7200}
	if cfg.PasswordResetExpiry() != 2*time.Hour {
		t.Errorf("PasswordResetExpiry: got %v, want 2h", cfg.PasswordResetExpiry())
	}
}

func TestEnvTest_EmailServiceAddress(t *testing.T) {
	cfg := &Config{EmailServiceHost: "mail.internal", EmailServicePort: 50053}
	want := "mail.internal:50053"
	if got := cfg.EmailServiceAddress(); got != want {
		t.Errorf("EmailServiceAddress: got %q, want %q", got, want)
	}
}

func TestEnvTest_EmailServiceAddress_DefaultPorts(t *testing.T) {
	clearGatewayEnv(t)
	cfg := Load()
	expected := "email-service:50053"
	if got := cfg.EmailServiceAddress(); got != expected {
		t.Errorf("EmailServiceAddress default: got %q, want %q", got, expected)
	}
}

func TestValidate_UsernameTakenBudgetNotNegative(t *testing.T) {
	cfg := Load()
	cfg.RateLimitUsernameTakenPerIP = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "GATEWAY_RATE_LIMIT_USERNAME_TAKEN_PER_IP") {
		t.Fatalf("Validate = %v, want the negative budget refused", err)
	}
}

func TestAccountMergeReauthMaxAge(t *testing.T) {
	c := &Config{}
	if got := c.AccountMergeReauthMaxAge(); got != DefaultAccountMergeReauthMaxAgeSeconds*time.Second {
		t.Fatalf("unset: got %v, want the default", got)
	}
	c.AccountMergeReauthMaxAgeSeconds = 60
	if got := c.AccountMergeReauthMaxAge(); got != time.Minute {
		t.Fatalf("set: got %v", got)
	}
	c.AccountMergeReauthMaxAgeSeconds = 86400
	if got := c.AccountMergeReauthMaxAge(); got != MaxAccountMergeReauthMaxAgeSeconds*time.Second {
		t.Fatalf("over the cap: got %v, want the cap", got)
	}
	c = Load()
	for _, v := range []int{-1, MaxAccountMergeReauthMaxAgeSeconds + 1} {
		c.AccountMergeReauthMaxAgeSeconds = v
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "GATEWAY_ACCOUNT_MERGE_REAUTH_MAX_AGE_SECONDS") {
			t.Fatalf("%d must be refused, got %v", v, err)
		}
	}
	c.AccountMergeReauthMaxAgeSeconds = MaxAccountMergeReauthMaxAgeSeconds
	if err := c.Validate(); err != nil {
		t.Fatalf("the cap itself is allowed: %v", err)
	}
}

func TestAgentsPerOwnerLimit(t *testing.T) {
	c := &Config{}
	if got := c.AgentsPerOwnerLimit(); got != DefaultAgentsMaxPerOwner {
		t.Fatalf("unset: got %d, want the default", got)
	}
	c.AgentsMaxPerOwner = 7
	if got := c.AgentsPerOwnerLimit(); got != 7 {
		t.Fatalf("set: got %d", got)
	}
	c.AgentsMaxPerOwner = MaxAgentsMaxPerOwner + 1
	if got := c.AgentsPerOwnerLimit(); got != MaxAgentsMaxPerOwner {
		t.Fatalf("over the cap: got %d, want the cap", got)
	}
	c = Load()
	for _, v := range []int{-1, MaxAgentsMaxPerOwner + 1} {
		c.AgentsMaxPerOwner = v
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "GATEWAY_AGENTS_MAX_PER_OWNER") {
			t.Fatalf("%d must be refused, got %v", v, err)
		}
	}
	for _, v := range []int{0, MaxAgentsMaxPerOwner} {
		c.AgentsMaxPerOwner = v
		if err := c.Validate(); err != nil {
			t.Fatalf("%d is allowed: %v", v, err)
		}
	}
}

// Agent accounts are opt-in.
func TestAgentsEnabled_DefaultsOff(t *testing.T) {
	t.Setenv("GATEWAY_AGENTS_ENABLED", "")
	if Load().AgentsEnabled {
		t.Fatal("agent accounts must default off")
	}
	t.Setenv("GATEWAY_AGENTS_ENABLED", "true")
	if !Load().AgentsEnabled {
		t.Fatal("GATEWAY_AGENTS_ENABLED=true must turn agent accounts on")
	}
}

func TestSelfServiceTenantsLimits(t *testing.T) {
	c := &Config{}
	if got := c.SelfServiceTenantsLimit(); got != DefaultSelfServiceTenantsMaxPerUser {
		t.Fatalf("unset limit: got %d, want the default", got)
	}
	if got := c.SelfServiceTenantsWindow(); got != DefaultSelfServiceTenantsWindowSeconds*time.Second {
		t.Fatalf("unset window: got %v, want the default", got)
	}
	c.SelfServiceTenantsMaxPerUser, c.SelfServiceTenantsWindowSeconds = 3, 60
	if got := c.SelfServiceTenantsLimit(); got != 3 {
		t.Fatalf("set limit: got %d", got)
	}
	if got := c.SelfServiceTenantsWindow(); got != time.Minute {
		t.Fatalf("set window: got %v", got)
	}
	c.SelfServiceTenantsMaxPerUser, c.SelfServiceTenantsWindowSeconds = MaxSelfServiceTenantsMaxPerUser+1, MaxSelfServiceTenantsWindowSeconds+1
	if got := c.SelfServiceTenantsLimit(); got != MaxSelfServiceTenantsMaxPerUser {
		t.Fatalf("limit over the cap: got %d, want the cap", got)
	}
	if got := c.SelfServiceTenantsWindow(); got != MaxSelfServiceTenantsWindowSeconds*time.Second {
		t.Fatalf("window over the cap: got %v, want the cap", got)
	}

	c = Load()
	for _, v := range []int{-1, MaxSelfServiceTenantsMaxPerUser + 1} {
		c.SelfServiceTenantsMaxPerUser = v
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "GATEWAY_SELF_SERVICE_TENANTS_MAX_PER_USER") {
			t.Fatalf("limit %d must be refused, got %v", v, err)
		}
	}
	c.SelfServiceTenantsMaxPerUser = 0
	for _, v := range []int{-1, MaxSelfServiceTenantsWindowSeconds + 1} {
		c.SelfServiceTenantsWindowSeconds = v
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "GATEWAY_SELF_SERVICE_TENANTS_WINDOW_SECONDS") {
			t.Fatalf("window %d must be refused, got %v", v, err)
		}
	}
	c.SelfServiceTenantsMaxPerUser, c.SelfServiceTenantsWindowSeconds = MaxSelfServiceTenantsMaxPerUser, MaxSelfServiceTenantsWindowSeconds
	if err := c.Validate(); err != nil {
		t.Fatalf("the caps themselves are allowed: %v", err)
	}
}

func TestTenantInvitationLimits(t *testing.T) {
	c := &Config{}
	if got := c.TenantInvitationLimit(); got != DefaultTenantInvitationMaxPerTenant {
		t.Fatalf("unset limit: got %d, want the default", got)
	}
	if got := c.TenantInvitationWindow(); got != DefaultTenantInvitationWindowSeconds*time.Second {
		t.Fatalf("unset window: got %v, want the default", got)
	}
	if got := c.TenantInvitationResendCooldown(); got != DefaultTenantInvitationResendCooldownSeconds*time.Second {
		t.Fatalf("unset cooldown: got %v, want the default", got)
	}
	c.TenantInvitationMaxPerTenant, c.TenantInvitationWindowSeconds, c.TenantInvitationResendCooldownSeconds = 3, 60, 30
	if got := c.TenantInvitationLimit(); got != 3 {
		t.Fatalf("set limit: got %d", got)
	}
	if got := c.TenantInvitationWindow(); got != time.Minute {
		t.Fatalf("set window: got %v", got)
	}
	if got := c.TenantInvitationResendCooldown(); got != 30*time.Second {
		t.Fatalf("set cooldown: got %v", got)
	}
	c.TenantInvitationMaxPerTenant = MaxTenantInvitationMaxPerTenant + 1
	c.TenantInvitationWindowSeconds = MaxTenantInvitationWindowSeconds + 1
	c.TenantInvitationResendCooldownSeconds = MaxTenantInvitationResendCooldownSeconds + 1
	if got := c.TenantInvitationLimit(); got != MaxTenantInvitationMaxPerTenant {
		t.Fatalf("limit over the cap: got %d, want the cap", got)
	}
	if got := c.TenantInvitationWindow(); got != MaxTenantInvitationWindowSeconds*time.Second {
		t.Fatalf("window over the cap: got %v, want the cap", got)
	}
	if got := c.TenantInvitationResendCooldown(); got != MaxTenantInvitationResendCooldownSeconds*time.Second {
		t.Fatalf("cooldown over the cap: got %v, want the cap", got)
	}

	for _, tc := range []struct {
		env string
		set func(*Config, int)
		max int
	}{
		{"GATEWAY_TENANT_INVITATION_MAX_PER_TENANT", func(c *Config, v int) { c.TenantInvitationMaxPerTenant = v }, MaxTenantInvitationMaxPerTenant},
		{"GATEWAY_TENANT_INVITATION_WINDOW_SECONDS", func(c *Config, v int) { c.TenantInvitationWindowSeconds = v }, MaxTenantInvitationWindowSeconds},
		{"GATEWAY_TENANT_INVITATION_RESEND_COOLDOWN_SECONDS", func(c *Config, v int) { c.TenantInvitationResendCooldownSeconds = v }, MaxTenantInvitationResendCooldownSeconds},
	} {
		for _, v := range []int{-1, tc.max + 1} {
			c := Load()
			tc.set(c, v)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.env) {
				t.Fatalf("%s=%d must be refused, got %v", tc.env, v, err)
			}
		}
		c := Load()
		tc.set(c, tc.max)
		if err := c.Validate(); err != nil {
			t.Fatalf("%s at its cap is allowed: %v", tc.env, err)
		}
	}

	t.Setenv("GATEWAY_TENANT_INVITATION_MAX_PER_TENANT", "7")
	t.Setenv("GATEWAY_TENANT_INVITATION_WINDOW_SECONDS", "120")
	t.Setenv("GATEWAY_TENANT_INVITATION_RESEND_COOLDOWN_SECONDS", "45")
	t.Setenv("GATEWAY_RATE_LIMIT_INVITATION_PER_IP", "9")
	c = Load()
	if c.TenantInvitationMaxPerTenant != 7 || c.TenantInvitationWindowSeconds != 120 ||
		c.TenantInvitationResendCooldownSeconds != 45 || c.RateLimitInvitationPerIP != 9 {
		t.Fatalf("env not read: %d %d %d %d", c.TenantInvitationMaxPerTenant,
			c.TenantInvitationWindowSeconds, c.TenantInvitationResendCooldownSeconds, c.RateLimitInvitationPerIP)
	}
}

// Self-service tenants are opt-in for the default project.
func TestSelfServiceTenantsEnabled_DefaultsOff(t *testing.T) {
	t.Setenv("GATEWAY_SELF_SERVICE_TENANTS_ENABLED", "")
	if Load().SelfServiceTenantsEnabled {
		t.Fatal("self-service tenants must default off")
	}
	t.Setenv("GATEWAY_SELF_SERVICE_TENANTS_ENABLED", "true")
	if !Load().SelfServiceTenantsEnabled {
		t.Fatal("GATEWAY_SELF_SERVICE_TENANTS_ENABLED=true must turn them on")
	}
}
