package config

import (
	"os"
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
		{"EntDBAddress", cfg.EntDBAddress, "entdb:50051"},
		{"DefaultTenantID", cfg.DefaultTenantID, "local"},
		{"EmailServiceHost", cfg.EmailServiceHost, "email-service"},
		{"EmailServicePort", cfg.EmailServicePort, 50053},
		{"JWTKeys", cfg.JWTKeys, ""},
		{"JWTExpirySeconds", cfg.JWTExpirySeconds, 900},
		{"RefreshExpirySeconds", cfg.RefreshExpirySeconds, 604800},
		{"GoogleClientID", cfg.GoogleClientID, ""},
		{"GoogleClientSecret", cfg.GoogleClientSecret, ""},
		{"MicrosoftClientID", cfg.MicrosoftClientID, ""},
		{"MicrosoftClientSecret", cfg.MicrosoftClientSecret, ""},
		{"MicrosoftTenantID", cfg.MicrosoftTenantID, ""},
		{"PasswordResetExpirySeconds", cfg.PasswordResetExpirySeconds, 3600},
		{"TOTPEncryptionKey", cfg.TOTPEncryptionKey, ""},
		{"TOTPIssuer", cfg.TOTPIssuer, "Glassa Work"},
		{"LoginChallengeExpirySeconds", cfg.LoginChallengeExpirySeconds, 300},
		{"PasskeyRPID", cfg.PasskeyRPID, "localhost"},
		{"PasskeyRPName", cfg.PasskeyRPName, "Glassa Work"},
		{"PasskeyOrigin", cfg.PasskeyOrigin, "http://localhost:9002"},
		{"PasskeyChallengeExpirySeconds", cfg.PasskeyChallengeExpirySeconds, 300},
		{"QRLoginBaseURL", cfg.QRLoginBaseURL, "http://localhost:9002"},
		{"QRLoginExpirySeconds", cfg.QRLoginExpirySeconds, 300},
		{"LoginMaxFailedAttempts", cfg.LoginMaxFailedAttempts, 5},
		{"LoginLockoutSeconds", cfg.LoginLockoutSeconds, 900},
		{"DefaultEmailDomain", cfg.DefaultEmailDomain, "glassa.work"},
		{"AllowedOrigins", cfg.AllowedOrigins, "http://localhost:9002,http://localhost:3000"},
		{"CookieDomain", cfg.CookieDomain, ""},
		{"CookieSecure", cfg.CookieSecure, false},
		{"CookieSameSite", cfg.CookieSameSite, "Lax"},
		{"AuthAllowLocal", cfg.AuthAllowLocal, true},
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
	os.Unsetenv("GATEWAY_GRPC_PORT")
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
