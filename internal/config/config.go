// Package config loads the identity service configuration from
// environment variables with the GATEWAY_ prefix.
//
// This is the Go port of backend/api_gateway/config.py. It uses
// os.Getenv with typed defaults — no external config library needed.
// Sensitive values (secrets, encryption keys, client secrets) are
// never logged.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all identity service configuration.
type Config struct {
	// Server
	GRPCPort    int
	ConnectPort int
	MetricsPort int

	// EntDB
	EntDBAddress string

	// Tenant
	DefaultTenantID string

	// Email service (internal gRPC)
	EmailServiceHost string
	EmailServicePort int

	// JWT (RS256)
	// JSON array: [{"kid":"k1","private_key_pem":"...","public_key_pem":"...","active":true}]
	// If empty and running locally, an ephemeral RSA key is auto-generated.
	JWTKeys          string
	JWTExpirySeconds int

	// Refresh tokens
	RefreshExpirySeconds int

	// OAuth providers. Identity does the code exchange for these
	// providers itself — see pkg/oauth. A provider is enabled only
	// when BOTH the ID and secret are non-empty.
	GoogleClientID        string
	GoogleClientSecret    string
	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftTenantID     string
	GitHubClientID        string
	GitHubClientSecret    string

	// Password
	PasswordResetExpirySeconds int

	// TOTP (2FA)
	// 32-byte key, base64-encoded. Required in prod; dev falls back to
	// a deterministic throwaway key.
	TOTPEncryptionKey string
	TOTPIssuer        string

	// Login challenge (how long after password success user has to complete 2FA)
	LoginChallengeExpirySeconds int

	// WebAuthn / Passkeys
	PasskeyRPID                   string
	PasskeyRPName                 string
	PasskeyOrigin                 string
	PasskeyChallengeExpirySeconds int

	// QR Login (cross-device authorization)
	QRLoginBaseURL       string
	QRLoginExpirySeconds int

	// Login security (failed-login lockout)
	LoginMaxFailedAttempts int
	LoginLockoutSeconds    int

	// Default email domain
	DefaultEmailDomain string

	// CORS
	AllowedOrigins string

	// Cookie settings
	CookieDomain   string
	CookieSecure   bool
	CookieSameSite string

	// Dev-only
	AuthAllowLocal bool

	// SMTP single-provider config (simple form). If SMTPProviders is set,
	// that takes precedence.
	SMTPHost string // GATEWAY_SMTP_HOST
	SMTPPort int    // GATEWAY_SMTP_PORT (default 587)
	SMTPUser string // GATEWAY_SMTP_USER
	SMTPPass string // GATEWAY_SMTP_PASS
	SMTPFrom string // GATEWAY_SMTP_FROM
	SMTPTLS  bool   // GATEWAY_SMTP_TLS (default true)

	// SMTP multi-provider JSON. If set, parsed as []email.SMTPConfig and
	// used as a chain in order. Overrides the single-provider env vars.
	SMTPProviders string // GATEWAY_SMTP_PROVIDERS

	// Public app URLs used in email links.
	AppBaseURL string // GATEWAY_APP_BASE_URL — e.g. "https://app.example.com"

	// How long an email-verification or password-reset token is valid for.
	EmailTokenExpirySeconds int // GATEWAY_EMAIL_TOKEN_EXPIRY_SECONDS (default 86400)

	// Postgres (alternate persistence driver). When PostgresDSN is set
	// the application bootstrapper may prefer the Postgres-backed
	// repository over EntDB; the actual driver selection lives in the
	// internal/repo package.
	//
	//   GATEWAY_POSTGRES_DSN          e.g. "postgres://user:pass@host:5432/identity?sslmode=disable"
	//   GATEWAY_POSTGRES_MAX_CONNS    pool size, default 25
	//   GATEWAY_POSTGRES_AUTO_MIGRATE run pending migrations on connect, default true
	PostgresDSN         string
	PostgresMaxConns    int
	PostgresAutoMigrate bool
}

// Load reads configuration from environment variables with GATEWAY_
// prefix, falling back to sensible defaults for local development.
func Load() *Config {
	return &Config{
		GRPCPort:    envInt("GATEWAY_GRPC_PORT", 50051),
		ConnectPort: envInt("GATEWAY_CONNECT_PORT", 80),
		MetricsPort: envInt("GATEWAY_METRICS_PORT", 9090),

		EntDBAddress: envStr("GATEWAY_ENTDB_ADDRESS", "entdb:50051"),

		DefaultTenantID: envStr("GATEWAY_DEFAULT_TENANT_ID", "local"),

		EmailServiceHost: envStr("GATEWAY_EMAIL_SERVICE_HOST", "email-service"),
		EmailServicePort: envInt("GATEWAY_EMAIL_SERVICE_PORT", 50053),

		JWTKeys:          envStr("GATEWAY_JWT_KEYS", ""),
		JWTExpirySeconds: envInt("GATEWAY_JWT_EXPIRY_SECONDS", 900),

		RefreshExpirySeconds: envInt("GATEWAY_REFRESH_EXPIRY_SECONDS", 604800),

		GoogleClientID:        envStr("GATEWAY_OAUTH_GOOGLE_CLIENT_ID", envStr("GATEWAY_GOOGLE_CLIENT_ID", "")),
		GoogleClientSecret:    envStr("GATEWAY_OAUTH_GOOGLE_CLIENT_SECRET", envStr("GATEWAY_GOOGLE_CLIENT_SECRET", "")),
		MicrosoftClientID:     envStr("GATEWAY_OAUTH_MICROSOFT_CLIENT_ID", envStr("GATEWAY_MICROSOFT_CLIENT_ID", "")),
		MicrosoftClientSecret: envStr("GATEWAY_OAUTH_MICROSOFT_CLIENT_SECRET", envStr("GATEWAY_MICROSOFT_CLIENT_SECRET", "")),
		MicrosoftTenantID:     envStr("GATEWAY_MICROSOFT_TENANT_ID", ""),
		GitHubClientID:        envStr("GATEWAY_OAUTH_GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:    envStr("GATEWAY_OAUTH_GITHUB_CLIENT_SECRET", ""),

		PasswordResetExpirySeconds: envInt("GATEWAY_PASSWORD_RESET_EXPIRY_SECONDS", 3600),

		TOTPEncryptionKey: envStr("GATEWAY_TOTP_ENCRYPTION_KEY", ""),
		TOTPIssuer:        envStr("GATEWAY_TOTP_ISSUER", "Glassa Work"),

		LoginChallengeExpirySeconds: envInt("GATEWAY_LOGIN_CHALLENGE_EXPIRY_SECONDS", 300),

		PasskeyRPID:                   envStr("GATEWAY_PASSKEY_RP_ID", "localhost"),
		PasskeyRPName:                 envStr("GATEWAY_PASSKEY_RP_NAME", "Glassa Work"),
		PasskeyOrigin:                 envStr("GATEWAY_PASSKEY_ORIGIN", "http://localhost:9002"),
		PasskeyChallengeExpirySeconds: envInt("GATEWAY_PASSKEY_CHALLENGE_EXPIRY_SECONDS", 300),

		QRLoginBaseURL:       envStr("GATEWAY_QR_LOGIN_BASE_URL", "http://localhost:9002"),
		QRLoginExpirySeconds: envInt("GATEWAY_QR_LOGIN_EXPIRY_SECONDS", 300),

		LoginMaxFailedAttempts: envInt("GATEWAY_LOGIN_MAX_FAILED_ATTEMPTS", 5),
		LoginLockoutSeconds:    envInt("GATEWAY_LOGIN_LOCKOUT_SECONDS", 900),

		DefaultEmailDomain: envStr("GATEWAY_DEFAULT_EMAIL_DOMAIN", "glassa.work"),

		AllowedOrigins: envStr("GATEWAY_ALLOWED_ORIGINS", "http://localhost:9002,http://localhost:3000"),

		CookieDomain:   envStr("GATEWAY_COOKIE_DOMAIN", ""),
		CookieSecure:   envBool("GATEWAY_COOKIE_SECURE", false),
		CookieSameSite: envStr("GATEWAY_COOKIE_SAMESITE", "Lax"),

		AuthAllowLocal: envBool("GATEWAY_AUTH_ALLOW_LOCAL", true),

		SMTPHost:      envStr("GATEWAY_SMTP_HOST", ""),
		SMTPPort:      envInt("GATEWAY_SMTP_PORT", 587),
		SMTPUser:      envStr("GATEWAY_SMTP_USER", ""),
		SMTPPass:      envStr("GATEWAY_SMTP_PASS", ""),
		SMTPFrom:      envStr("GATEWAY_SMTP_FROM", ""),
		SMTPTLS:       envBool("GATEWAY_SMTP_TLS", true),
		SMTPProviders: envStr("GATEWAY_SMTP_PROVIDERS", ""),

		AppBaseURL:              envStr("GATEWAY_APP_BASE_URL", "http://localhost:9002"),
		EmailTokenExpirySeconds: envInt("GATEWAY_EMAIL_TOKEN_EXPIRY_SECONDS", 86400),

		PostgresDSN:         envStr("GATEWAY_POSTGRES_DSN", ""),
		PostgresMaxConns:    envInt("GATEWAY_POSTGRES_MAX_CONNS", 25),
		PostgresAutoMigrate: envBool("GATEWAY_POSTGRES_AUTO_MIGRATE", true),
	}
}

// JWTExpiry returns the JWT expiry as a time.Duration.
func (c *Config) JWTExpiry() time.Duration {
	return time.Duration(c.JWTExpirySeconds) * time.Second
}

// RefreshExpiry returns the refresh token expiry as a time.Duration.
func (c *Config) RefreshExpiry() time.Duration {
	return time.Duration(c.RefreshExpirySeconds) * time.Second
}

// PasswordResetExpiry returns the password reset expiry as a time.Duration.
func (c *Config) PasswordResetExpiry() time.Duration {
	return time.Duration(c.PasswordResetExpirySeconds) * time.Second
}

// EmailServiceAddress returns the host:port for the email service.
func (c *Config) EmailServiceAddress() string {
	return c.EmailServiceHost + ":" + strconv.Itoa(c.EmailServicePort)
}

// envStr reads a string environment variable, returning def if unset or empty.
func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envInt reads an integer environment variable. Returns def if the
// variable is unset, empty, or not a valid integer.
func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// envBool reads a boolean environment variable. Recognises "true",
// "1", "yes" (case-insensitive) as true, and "false", "0", "no" as
// false. Returns def for any other value or when unset.
func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return def
	}
}
