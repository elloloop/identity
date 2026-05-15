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

	// Persistence driver. Selects which Repository / DB
	// implementation the binary wires up — "entdb" (default), "memory"
	// for an in-process store useful for local dev, or "postgres"
	// once the Postgres driver lands. Driven by GATEWAY_REPO_DRIVER.
	RepoDriver string

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

	// JWT audience. When non-empty, minted access tokens carry this as
	// the "aud" claim and the verifier enforces a match. When
	// JWTRequireAudience is true, tokens with no "aud" claim are also
	// rejected; the false default exists so a deploy can roll out the
	// mint-side change first, wait for in-flight tokens to expire, then
	// flip to required.
	JWTAudience        string
	JWTRequireAudience bool

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

	// Identity Verification (document + selfie). The provider name
	// selects the implementation in pkg/idv. Empty disables IDV; the
	// RPCs return CodeUnimplemented to clients in that case.
	IDVProvider           string // "azure", "stub", or "" (disabled)
	IDVAzureEndpoint      string // e.g. https://my-face.cognitiveservices.azure.com
	IDVAzureKey           string // Cognitive Services key
	IDVAzureSessionTTLSec int    // session token lifetime; default 600
	// When true, PasswordLogin / OAuthLogin reject users without an
	// approved identity verification. The default is false (verification
	// is offered but not required) to match the existing email-verified
	// pattern. Tenants that need stricter onboarding flip this on.
	IDVRequired bool

	// Password
	PasswordSignupEnabled      bool
	PasswordResetEnabled       bool
	PasswordResetExpirySeconds int

	// TOTP (2FA)
	// 32-byte key, base64-encoded. Required in prod; dev falls back to
	// a deterministic throwaway key.
	TOTPEncryptionKey string
	TOTPIssuer        string

	// Pepper used as the HMAC-SHA-256 key for recovery-code hashing.
	// Base64-encoded; must decode to >= 32 bytes. Required whenever
	// TOTPEncryptionKey is set (i.e. any non-dev deployment). The
	// pepper turns a stolen DB into a brute-force-resistant artifact:
	// without it, an attacker cannot precompute or enumerate hashes.
	TOTPRecoveryPepper string

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

	// Per-recipient cooldown between transactional email sends. Defeats
	// inbox-bombing via repeated unauthenticated RequestPasswordReset /
	// SendEmailVerification calls. In-memory per replica.
	EmailSendCooldownSeconds int // GATEWAY_EMAIL_SEND_COOLDOWN_SECONDS (default 60)

	// Per-email cooldown on PasswordSignup. Throttled signups return
	// the same anti-enumeration decoy as a duplicate-email signup so the
	// endpoint cannot be used to probe for which addresses are
	// rate-limited (which would itself reveal recent attempts).
	// Complements the per-IP rate limit at the middleware layer.
	SignupEmailCooldownSeconds int // GATEWAY_SIGNUP_EMAIL_COOLDOWN_SECONDS (default 60)

	// Audit log queue depth for the async flusher. Drops happen if the
	// auth hot path produces events faster than EntDB can absorb them.
	// Surface via audit.Logger.DroppedCount() on a metric.
	AuditQueueSize int // GATEWAY_AUDIT_QUEUE_SIZE (default 4096)

	// Maximum HTTP request body size in bytes, enforced via
	// http.MaxBytesHandler so a slow-POST / oversize-payload attacker
	// can't exhaust memory. Default 1 MiB — auth RPC bodies are tiny.
	HTTPMaxBodyBytes int64 // GATEWAY_HTTP_MAX_BODY_BYTES (default 1048576)

	// Trusted proxies: comma-separated list of CIDRs whose
	// X-Forwarded-For headers the service will honour. Anything outside
	// these ranges is treated as an untrusted client and its forwarded
	// headers are ignored — TCP peer IP is used instead.
	TrustedProxies string // GATEWAY_TRUSTED_PROXIES (default "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32,::1/128")

	// Rate-limit configuration. The in-memory token bucket is keyed by
	// client IP. quotas are requests-per-window per IP. Set to 0 to
	// disable the per-endpoint limiter.
	RateLimitWindowSeconds int // GATEWAY_RATE_LIMIT_WINDOW_SECONDS (default 60)
	RateLimitSignupPerIP   int // GATEWAY_RATE_LIMIT_SIGNUP_PER_IP (default 10/min)
	RateLimitLoginPerIP    int // GATEWAY_RATE_LIMIT_LOGIN_PER_IP (default 30/min)
	RateLimitResetPerIP    int // GATEWAY_RATE_LIMIT_RESET_PER_IP (default 5/min)
	RateLimitVerifyPerIP   int // GATEWAY_RATE_LIMIT_VERIFY_PER_IP (default 20/min)

	// Postgres (alternate persistence driver). When PostgresDSN is set
	// the application bootstrapper may prefer the Postgres-backed
	// repository over EntDB; the actual driver selection lives in the
	// internal/repo package.
	//
	//   GATEWAY_POSTGRES_DSN          e.g. "postgres://user:pass@host:5432/identity?sslmode=disable"
	//   GATEWAY_POSTGRES_MAX_CONNS    pool size, default 25
	//   GATEWAY_POSTGRES_AUTO_MIGRATE run pending migrations on connect, default false
	//                                 (production: run migrations out-of-band as a
	//                                  separate Job; setting this true on a rolling
	//                                  deploy can race multiple replicas).
	PostgresDSN         string
	PostgresMaxConns    int
	PostgresAutoMigrate bool

	// OTel exports OpenTelemetry traces to a deployer-supplied OTLP
	// collector. Default off so a deployer who has no collector pays
	// zero cost — when disabled the no-op tracer is installed and the
	// otelconnect interceptor is omitted from the handler chain.
	//
	//   GATEWAY_OTEL_ENABLED            true|false (default false)
	//   GATEWAY_OTEL_EXPORTER_ENDPOINT  host:port — required when enabled
	//   GATEWAY_OTEL_EXPORTER_PROTOCOL  grpc|http (default grpc)
	//   GATEWAY_OTEL_SAMPLE_RATIO       0.0–1.0 (default 0.1)
	//   GATEWAY_OTEL_DEPLOYMENT_ENV     deployment.environment.name (default "")
	//   GATEWAY_OTEL_SERVICE_VERSION    overrides build version baked into the binary
	OTelEnabled          bool
	OTelExporterEndpoint string
	OTelExporterProtocol string
	OTelSampleRatio      float64
	OTelDeploymentEnv    string
	OTelServiceVersion   string

	// Sweeper (#94). A background goroutine periodically deletes
	// expired-but-uncollected rows from five ephemeral tables
	// (WebAuthn challenges, email-verification / password-reset /
	// email-change tokens, login challenges). Without GC these
	// tables grow unboundedly with the abandoned-flow rate.
	//
	//   GATEWAY_SWEEPER_INTERVAL_SECONDS  tick interval; 0 disables sweeping
	//                                     entirely (useful for tests and for
	//                                     deployers who run their own GC).
	//   GATEWAY_SWEEPER_BATCH_SIZE        per-table per-tick deletion cap.
	//   GATEWAY_SWEEPER_GRACE_SECONDS     additional grace past expires_at
	//                                     before a row is eligible to delete;
	//                                     covers in-flight flows that just
	//                                     consumed the token.
	SweeperIntervalSeconds int
	SweeperBatchSize       int
	SweeperGraceSeconds    int
}

// Load reads configuration from environment variables with GATEWAY_
// prefix, falling back to sensible defaults for local development.
func Load() *Config {
	return &Config{
		GRPCPort:    envInt("GATEWAY_GRPC_PORT", 50051),
		ConnectPort: envInt("GATEWAY_CONNECT_PORT", 80),
		MetricsPort: envInt("GATEWAY_METRICS_PORT", 9090),

		RepoDriver:   envStr("GATEWAY_REPO_DRIVER", "entdb"),
		EntDBAddress: envStr("GATEWAY_ENTDB_ADDRESS", "entdb:50051"),

		DefaultTenantID: envStr("GATEWAY_DEFAULT_TENANT_ID", "local"),

		EmailServiceHost: envStr("GATEWAY_EMAIL_SERVICE_HOST", "email-service"),
		EmailServicePort: envInt("GATEWAY_EMAIL_SERVICE_PORT", 50053),

		JWTKeys:            envStr("GATEWAY_JWT_KEYS", ""),
		JWTExpirySeconds:   envInt("GATEWAY_JWT_EXPIRY_SECONDS", 900),
		JWTAudience:        envStr("GATEWAY_JWT_AUDIENCE", ""),
		JWTRequireAudience: envBool("GATEWAY_JWT_REQUIRE_AUD", false),

		RefreshExpirySeconds: envInt("GATEWAY_REFRESH_EXPIRY_SECONDS", 604800),

		GoogleClientID:        envStr("GATEWAY_OAUTH_GOOGLE_CLIENT_ID", envStr("GATEWAY_GOOGLE_CLIENT_ID", "")),
		GoogleClientSecret:    envStr("GATEWAY_OAUTH_GOOGLE_CLIENT_SECRET", envStr("GATEWAY_GOOGLE_CLIENT_SECRET", "")),
		MicrosoftClientID:     envStr("GATEWAY_OAUTH_MICROSOFT_CLIENT_ID", envStr("GATEWAY_MICROSOFT_CLIENT_ID", "")),
		MicrosoftClientSecret: envStr("GATEWAY_OAUTH_MICROSOFT_CLIENT_SECRET", envStr("GATEWAY_MICROSOFT_CLIENT_SECRET", "")),
		MicrosoftTenantID:     envStr("GATEWAY_MICROSOFT_TENANT_ID", ""),
		GitHubClientID:        envStr("GATEWAY_OAUTH_GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:    envStr("GATEWAY_OAUTH_GITHUB_CLIENT_SECRET", ""),

		IDVProvider:           envStr("GATEWAY_IDV_PROVIDER", ""),
		IDVAzureEndpoint:      envStr("GATEWAY_IDV_AZURE_ENDPOINT", ""),
		IDVAzureKey:           envStr("GATEWAY_IDV_AZURE_KEY", ""),
		IDVAzureSessionTTLSec: envInt("GATEWAY_IDV_AZURE_SESSION_TTL_SECONDS", 600),
		IDVRequired:           envBool("GATEWAY_IDV_REQUIRED", false),

		PasswordSignupEnabled:      envBool("GATEWAY_PASSWORD_SIGNUP_ENABLED", true),
		PasswordResetEnabled:       envBool("GATEWAY_PASSWORD_RESET_ENABLED", true),
		PasswordResetExpirySeconds: envInt("GATEWAY_PASSWORD_RESET_EXPIRY_SECONDS", 900),

		TOTPEncryptionKey:  envStr("GATEWAY_TOTP_ENCRYPTION_KEY", ""),
		TOTPIssuer:         envStr("GATEWAY_TOTP_ISSUER", "Glassa Work"),
		TOTPRecoveryPepper: envStr("GATEWAY_TOTP_RECOVERY_PEPPER", ""),

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

		AppBaseURL:                 envStr("GATEWAY_APP_BASE_URL", "http://localhost:9002"),
		EmailTokenExpirySeconds:    envInt("GATEWAY_EMAIL_TOKEN_EXPIRY_SECONDS", 86400),
		EmailSendCooldownSeconds:   envInt("GATEWAY_EMAIL_SEND_COOLDOWN_SECONDS", 60),
		SignupEmailCooldownSeconds: envInt("GATEWAY_SIGNUP_EMAIL_COOLDOWN_SECONDS", 60),
		AuditQueueSize:             envInt("GATEWAY_AUDIT_QUEUE_SIZE", 4096),

		HTTPMaxBodyBytes: int64(envInt("GATEWAY_HTTP_MAX_BODY_BYTES", 1<<20)),

		TrustedProxies: envStr(
			"GATEWAY_TRUSTED_PROXIES",
			"10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32,::1/128",
		),

		RateLimitWindowSeconds: envInt("GATEWAY_RATE_LIMIT_WINDOW_SECONDS", 60),
		RateLimitSignupPerIP:   envInt("GATEWAY_RATE_LIMIT_SIGNUP_PER_IP", 10),
		RateLimitLoginPerIP:    envInt("GATEWAY_RATE_LIMIT_LOGIN_PER_IP", 30),
		RateLimitResetPerIP:    envInt("GATEWAY_RATE_LIMIT_RESET_PER_IP", 5),
		RateLimitVerifyPerIP:   envInt("GATEWAY_RATE_LIMIT_VERIFY_PER_IP", 20),

		PostgresDSN:         envStr("GATEWAY_POSTGRES_DSN", ""),
		PostgresMaxConns:    envInt("GATEWAY_POSTGRES_MAX_CONNS", 25),
		PostgresAutoMigrate: envBool("GATEWAY_POSTGRES_AUTO_MIGRATE", false),

		OTelEnabled:          envBool("GATEWAY_OTEL_ENABLED", false),
		OTelExporterEndpoint: envStr("GATEWAY_OTEL_EXPORTER_ENDPOINT", ""),
		OTelExporterProtocol: envStr("GATEWAY_OTEL_EXPORTER_PROTOCOL", "grpc"),
		OTelSampleRatio:      envFloat("GATEWAY_OTEL_SAMPLE_RATIO", 0.1),
		OTelDeploymentEnv:    envStr("GATEWAY_OTEL_DEPLOYMENT_ENV", ""),
		OTelServiceVersion:   envStr("GATEWAY_OTEL_SERVICE_VERSION", ""),

		SweeperIntervalSeconds: envInt("GATEWAY_SWEEPER_INTERVAL_SECONDS", 300),
		SweeperBatchSize:       envInt("GATEWAY_SWEEPER_BATCH_SIZE", 500),
		SweeperGraceSeconds:    envInt("GATEWAY_SWEEPER_GRACE_SECONDS", 60),
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

// envFloat reads a float64 environment variable. Returns def if the
// variable is unset, empty, or not a valid float.
func envFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
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
