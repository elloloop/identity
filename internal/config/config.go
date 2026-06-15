// Package config loads the identity service configuration from
// environment variables with the GATEWAY_ prefix.
//
// This is the Go port of backend/api_gateway/config.py. It uses
// os.Getenv with typed defaults — no external config library needed.
// Sensitive values (secrets, encryption keys, client secrets) are
// never logged.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// RevocationMode names the two refresh-token revocation models the
// service supports. See the Config.RevocationMode comment for the
// semantics; the two-mode contract is in docs/IDENTITY.md decision
// log §6.
type RevocationMode string

const (
	// RevocationModeTTL keeps the existing zero-cost hot path.
	// DeleteRefreshTokensForUser deletes refresh tokens; in-flight
	// access tokens stay valid until natural JWT expiry. The default.
	RevocationModeTTL RevocationMode = "ttl"

	// RevocationModeSession mints access tokens with an `sid` claim
	// referencing a Session row. The verification middleware reads
	// that row (via an in-process cache) and rejects the request when
	// the session is revoked.
	RevocationModeSession RevocationMode = "session"

	// RevocationModeTTLAccessTokenCap is the maximum access-token TTL
	// (seconds) compatible with the `ttl` revocation model. A deployer
	// who needs a longer-lived access token must switch to
	// `RevocationModeSession`, where cache TTL bounds the revocation
	// latency.
	RevocationModeTTLAccessTokenCap = 900
)

// CAPTCHA provider names accepted in GATEWAY_CAPTCHA_PROVIDER. They mirror
// the captcha.Provider* constants; config validates against these without
// importing pkg/captcha (config has no dependencies on the service tree).
const (
	CaptchaProviderTurnstile   = "turnstile"
	CaptchaProviderRecaptchaV3 = "recaptcha_v3"

	// DefaultCaptchaRecaptchaScoreThreshold is the reCAPTCHA v3 score below
	// which a response is rejected when no threshold is configured.
	DefaultCaptchaRecaptchaScoreThreshold = 0.5
)

// DefaultProjectIDFallback is the project id used when none is configured.
// It is the env-loader default for GATEWAY_DEFAULT_PROJECT_ID and the value
// app.New normalizes an empty DefaultProjectID to, so a directly-constructed
// Config (tests, embedding callers) never reaches the repo boundary with an
// empty project shard id. The single source of truth for this literal.
const DefaultProjectIDFallback = "default"

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

	// DefaultProjectID is the id of the control-plane Project the service
	// seeds on boot (postgres driver) and pins zero-config requests to. It
	// is a logical control-plane entity that MAPS ONTO the storage scope
	// DefaultTenantID — the two are distinct values and must not be
	// conflated. Driven by GATEWAY_DEFAULT_PROJECT_ID (default "default").
	// Only the postgres driver has a control plane; entdb/memory ignore it.
	DefaultProjectID string

	// AdminAPISecret is the shared secret that authenticates the
	// control-plane admin RPCs (AdminCreateProject and friends), which a
	// PLATFORM operator uses to provision projects/tenants out-of-band.
	// These RPCs are NOT user-authenticated: a caller proves it is the
	// operator by presenting this exact value in the
	// middleware.AdminAPISecretHeader header, compared in constant time.
	//
	// Empty (the default) DISABLES the admin RPCs entirely — they return
	// CodeUnimplemented — so a deployer who never sets it cannot have them
	// reached. Driven by GATEWAY_ADMIN_API_SECRET. Only the postgres driver
	// has a control plane; entdb/memory ignore it.
	//
	// TODO(redesign): the shared secret is the shipped mechanism. Future
	// work hardens this with mTLS client-certificate auth and an optional
	// internal-only listener port bound away from the public RPC surface.
	AdminAPISecret string

	// DefaultProjectAuthDomains is a comma-separated list of serving
	// hostnames seeded onto the default project at boot (postgres driver),
	// so the Host→project resolver maps these branded hostnames to the
	// default project. The FIRST entry is the primary auth-domain (used to
	// build branded links and cookie domains); the rest are additional
	// serving hosts. All are seeded VERIFIED — they are deployer-owned (a
	// customer-supplied custom domain goes through DNS verification
	// instead). Empty disables seeding. Driven by
	// GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS.
	DefaultProjectAuthDomains string

	// Email service (internal gRPC)
	EmailServiceHost string
	EmailServicePort int

	// JWT (RS256). Two backends ship in-tree:
	//
	//   file     (default) reads the keys file at GATEWAY_JWT_KEYS_FILE,
	//            reloads on SIGHUP. The default for any non-KMS
	//            deployment; works without external dependencies. If
	//            JWTKeysFile is empty, the binary auto-generates a
	//            throwaway dev key in a temp file at startup (suitable
	//            for local dev / CI only — emits a warning log).
	//   kms_aws  delegates Sign to AWS KMS. JWTKMSKeys is a CSV of
	//            "kid=keyARN" entries.
	//
	// Adding a new backend (GCP KMS, HashiCorp Vault, hardware HSM, …)
	// is a matter of implementing pkg/jwt.Signer in a sibling package.
	JWTSigner        string
	JWTKeysFile      string
	JWTKMSKeys       string
	JWTKMSAWSRegion  string
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

	// Revocation mode. Selects how the service propagates a
	// DeleteRefreshTokensForUser to in-flight access tokens.
	//
	//   "ttl"     (default) — refresh tokens are deleted; already-minted
	//             access tokens stay valid until natural JWT expiry. Zero
	//             hot-path cost. Hard startup assertion:
	//             `JWTExpirySeconds <= 900` so a deployer cannot raise the
	//             access-token lifetime without explicitly switching modes.
	//   "session" — opt-in. Access tokens carry an `sid` claim referencing
	//             a Session row; the verification middleware reads that
	//             row (via an in-process cache, configurable below) and
	//             rejects the request when `revoked_at_ms != 0`.
	//             DeleteRefreshTokensForUser additionally triggers
	//             RevokeSessionsForUser so the existing replay-detection
	//             code path also kills the access tokens.
	//
	// See docs/IDENTITY.md decision log §6 for the two-mode contract.
	RevocationMode RevocationMode

	// SessionCacheTTLSeconds bounds how long a session-state read from the
	// in-process cache may serve "active" before being re-read from the
	// repository. 0 = strict mode: every authenticated request reads the
	// row. Effective only when RevocationMode == RevocationModeSession.
	SessionCacheTTLSeconds int

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

	// OAuthAllowedReturnURLs is the comma-separated allowlist of app URLs
	// the hosted OAuth flow may redirect back to (the `return_to` param of
	// GET /oauth/start/{provider}). Each entry is an exact origin or a URL
	// prefix; a return_to matches when it equals an entry or begins with
	// an entry. Validation is fail-closed: a return_to that matches no
	// entry is rejected with 400.
	//
	// Empty disables the hosted flow entirely — GET /oauth/start and GET
	// /oauth/callback return 404. The headless BeginOAuthLogin / OAuthLogin
	// RPCs are unaffected. Driven by GATEWAY_OAUTH_ALLOWED_RETURN_URLS.
	OAuthAllowedReturnURLs string

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

	// CAPTCHA verification on unauthenticated endpoints. CaptchaEnabled is
	// the global on/off; when off the no-op verifier is wired and the
	// per-endpoint toggles are ignored. CaptchaProvider selects the
	// implementation in pkg/captcha ("turnstile" or "recaptcha_v3"); the
	// matching secret must be set. The per-endpoint toggles let a deployer
	// enforce CAPTCHA on a subset of the gated endpoints (all default true,
	// so enabling CAPTCHA gates every endpoint unless one is flipped off).
	CaptchaEnabled                 bool    // GATEWAY_CAPTCHA_ENABLED (default false)
	CaptchaProvider                string  // GATEWAY_CAPTCHA_PROVIDER ("turnstile" | "recaptcha_v3" | "")
	CaptchaTurnstileSecret         string  // GATEWAY_CAPTCHA_TURNSTILE_SECRET
	CaptchaRecaptchaSecret         string  // GATEWAY_CAPTCHA_RECAPTCHA_SECRET
	CaptchaRecaptchaScoreThreshold float64 // GATEWAY_CAPTCHA_RECAPTCHA_SCORE_THRESHOLD (default 0.5)
	CaptchaEnforcePasswordSignup   bool    // GATEWAY_CAPTCHA_ENFORCE_PASSWORD_SIGNUP (default true)
	CaptchaEnforcePasswordLogin    bool    // GATEWAY_CAPTCHA_ENFORCE_PASSWORD_LOGIN (default true)
	CaptchaEnforcePasswordReset    bool    // GATEWAY_CAPTCHA_ENFORCE_PASSWORD_RESET (default true)
	CaptchaEnforceEmailLoginCode   bool    // GATEWAY_CAPTCHA_ENFORCE_EMAIL_LOGIN_CODE (default true)
	CaptchaEnforceMagicLink        bool    // GATEWAY_CAPTCHA_ENFORCE_MAGIC_LINK (default true)

	// Password
	PasswordSignupEnabled      bool
	PasswordResetEnabled       bool
	PasswordResetExpirySeconds int

	// Passwordless email login (OTP code + magic link).
	//
	// PasswordlessSignupEnabled (default true) gates auto-create: when a
	// passwordless login verifies an email with no existing account and
	// this is true, the account is created on the spot; when false the
	// unknown email gets the same anti-enumeration decoy a request for a
	// known email would produce, so the endpoint never reveals which
	// addresses exist. Mirrors GATEWAY_PASSWORD_SIGNUP_ENABLED.
	PasswordlessSignupEnabled bool // GATEWAY_PASSWORDLESS_SIGNUP_ENABLED (default true)
	// OTP code lifetime, length is fixed at 6 digits.
	PasswordlessCodeTTLSeconds int // GATEWAY_PASSWORDLESS_CODE_TTL_SECONDS (default 300)
	// Max verify attempts per OTP before it is invalidated (brute-force cap).
	PasswordlessCodeMaxAttempts int // GATEWAY_PASSWORDLESS_CODE_MAX_ATTEMPTS (default 5)
	// Magic-link token lifetime.
	PasswordlessMagicLinkTTLSeconds int // GATEWAY_PASSWORDLESS_MAGIC_LINK_TTL_SECONDS (default 900)

	// Phone verification (SMS OTP). Standalone phone-ownership
	// verification for an already-authenticated user — not yet a login
	// factor. Disabled by default; when SMSEnabled is true a provider and
	// its credentials must be set (enforced by Validate).
	SMSEnabled  bool   // GATEWAY_SMS_ENABLED (default false)
	SMSProvider string // GATEWAY_SMS_PROVIDER: twilio | sns | azure

	// Twilio credentials (SMSProvider == twilio).
	SMSTwilioAccountSID string // GATEWAY_SMS_TWILIO_ACCOUNT_SID
	SMSTwilioAuthToken  string // GATEWAY_SMS_TWILIO_AUTH_TOKEN
	SMSTwilioFrom       string // GATEWAY_SMS_TWILIO_FROM

	// AWS SNS credentials (SMSProvider == sns).
	SMSAWSRegion          string // GATEWAY_SMS_AWS_REGION
	SMSAWSAccessKeyID     string // GATEWAY_SMS_AWS_ACCESS_KEY_ID
	SMSAWSSecretAccessKey string // GATEWAY_SMS_AWS_SECRET_ACCESS_KEY
	SMSAWSSenderID        string // GATEWAY_SMS_AWS_SENDER_ID (optional)

	// Azure Communication Services credentials (SMSProvider == azure).
	SMSAzureConnectionString string // GATEWAY_SMS_AZURE_CONNECTION_STRING
	SMSAzureFrom             string // GATEWAY_SMS_AZURE_FROM

	// Phone-verification OTP policy (mirrors the Passwordless* knobs).
	PhoneCodeTTLSeconds      int // GATEWAY_PHONE_CODE_TTL_SECONDS (default 300)
	PhoneCodeMaxAttempts     int // GATEWAY_PHONE_CODE_MAX_ATTEMPTS (default 5)
	PhoneCodeCooldownSeconds int // GATEWAY_PHONE_CODE_COOLDOWN_SECONDS (default 60)

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

	// PublicEmailDomains extends the built-in set of consumer/public email
	// providers (gmail, outlook, yahoo, …) used by IsPublicEmailDomain. A
	// verified email under a public domain does NOT imply company
	// affiliation, so a tenant is never auto-formed from one. Comma-
	// separated; entries are punycode-canonicalised. Driven by
	// GATEWAY_PUBLIC_EMAIL_DOMAINS (default empty — the built-in set
	// already covers the major global providers).
	PublicEmailDomains string

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

	// How long a tenant-membership invitation is valid for before it must be
	// reissued. Longer than an email token because joining a team is a less
	// time-sensitive action than a password reset.
	TenantInvitationExpirySeconds int // GATEWAY_TENANT_INVITATION_EXPIRY_SECONDS (default 604800 = 7 days)

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
	RateLimitWindowSeconds     int // GATEWAY_RATE_LIMIT_WINDOW_SECONDS (default 60)
	RateLimitSignupPerIP       int // GATEWAY_RATE_LIMIT_SIGNUP_PER_IP (default 10/min)
	RateLimitLoginPerIP        int // GATEWAY_RATE_LIMIT_LOGIN_PER_IP (default 30/min)
	RateLimitResetPerIP        int // GATEWAY_RATE_LIMIT_RESET_PER_IP (default 5/min)
	RateLimitVerifyPerIP       int // GATEWAY_RATE_LIMIT_VERIFY_PER_IP (default 20/min)
	RateLimitPasswordlessPerIP int // GATEWAY_RATE_LIMIT_PASSWORDLESS_PER_IP (default 5/min) — RequestEmailLoginCode + RequestMagicLink
	RateLimitPhonePerIP        int // GATEWAY_RATE_LIMIT_PHONE_PER_IP (default 5/min) — RequestPhoneVerification

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

		DefaultTenantID:           envStr("GATEWAY_DEFAULT_TENANT_ID", "local"),
		DefaultProjectID:          envStr("GATEWAY_DEFAULT_PROJECT_ID", DefaultProjectIDFallback),
		AdminAPISecret:            envStr("GATEWAY_ADMIN_API_SECRET", ""),
		DefaultProjectAuthDomains: envStr("GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS", ""),

		EmailServiceHost: envStr("GATEWAY_EMAIL_SERVICE_HOST", "email-service"),
		EmailServicePort: envInt("GATEWAY_EMAIL_SERVICE_PORT", 50053),

		JWTSigner:          envStr("GATEWAY_JWT_SIGNER", "file"),
		JWTKeysFile:        envStr("GATEWAY_JWT_KEYS_FILE", ""),
		JWTKMSKeys:         envStr("GATEWAY_JWT_KMS_KEYS", ""),
		JWTKMSAWSRegion:    envStr("GATEWAY_JWT_KMS_AWS_REGION", ""),
		JWTExpirySeconds:   envInt("GATEWAY_JWT_EXPIRY_SECONDS", 900),
		JWTAudience:        envStr("GATEWAY_JWT_AUDIENCE", ""),
		JWTRequireAudience: envBool("GATEWAY_JWT_REQUIRE_AUD", false),

		RefreshExpirySeconds: envInt("GATEWAY_REFRESH_EXPIRY_SECONDS", 604800),

		RevocationMode:         revocationModeFromEnv("GATEWAY_REVOCATION_MODE", RevocationModeTTL),
		SessionCacheTTLSeconds: envInt("GATEWAY_SESSION_CACHE_TTL_SECONDS", 60),

		GoogleClientID:        envStr("GATEWAY_OAUTH_GOOGLE_CLIENT_ID", envStr("GATEWAY_GOOGLE_CLIENT_ID", "")),
		GoogleClientSecret:    envStr("GATEWAY_OAUTH_GOOGLE_CLIENT_SECRET", envStr("GATEWAY_GOOGLE_CLIENT_SECRET", "")),
		MicrosoftClientID:     envStr("GATEWAY_OAUTH_MICROSOFT_CLIENT_ID", envStr("GATEWAY_MICROSOFT_CLIENT_ID", "")),
		MicrosoftClientSecret: envStr("GATEWAY_OAUTH_MICROSOFT_CLIENT_SECRET", envStr("GATEWAY_MICROSOFT_CLIENT_SECRET", "")),
		MicrosoftTenantID:     envStr("GATEWAY_MICROSOFT_TENANT_ID", ""),
		GitHubClientID:        envStr("GATEWAY_OAUTH_GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:    envStr("GATEWAY_OAUTH_GITHUB_CLIENT_SECRET", ""),

		OAuthAllowedReturnURLs: envStr("GATEWAY_OAUTH_ALLOWED_RETURN_URLS", ""),

		IDVProvider:           envStr("GATEWAY_IDV_PROVIDER", ""),
		IDVAzureEndpoint:      envStr("GATEWAY_IDV_AZURE_ENDPOINT", ""),
		IDVAzureKey:           envStr("GATEWAY_IDV_AZURE_KEY", ""),
		IDVAzureSessionTTLSec: envInt("GATEWAY_IDV_AZURE_SESSION_TTL_SECONDS", 600),
		IDVRequired:           envBool("GATEWAY_IDV_REQUIRED", false),

		CaptchaEnabled:                 envBool("GATEWAY_CAPTCHA_ENABLED", false),
		CaptchaProvider:                envStr("GATEWAY_CAPTCHA_PROVIDER", ""),
		CaptchaTurnstileSecret:         envStr("GATEWAY_CAPTCHA_TURNSTILE_SECRET", ""),
		CaptchaRecaptchaSecret:         envStr("GATEWAY_CAPTCHA_RECAPTCHA_SECRET", ""),
		CaptchaRecaptchaScoreThreshold: envFloat("GATEWAY_CAPTCHA_RECAPTCHA_SCORE_THRESHOLD", DefaultCaptchaRecaptchaScoreThreshold),
		CaptchaEnforcePasswordSignup:   envBool("GATEWAY_CAPTCHA_ENFORCE_PASSWORD_SIGNUP", true),
		CaptchaEnforcePasswordLogin:    envBool("GATEWAY_CAPTCHA_ENFORCE_PASSWORD_LOGIN", true),
		CaptchaEnforcePasswordReset:    envBool("GATEWAY_CAPTCHA_ENFORCE_PASSWORD_RESET", true),
		CaptchaEnforceEmailLoginCode:   envBool("GATEWAY_CAPTCHA_ENFORCE_EMAIL_LOGIN_CODE", true),
		CaptchaEnforceMagicLink:        envBool("GATEWAY_CAPTCHA_ENFORCE_MAGIC_LINK", true),

		PasswordSignupEnabled:      envBool("GATEWAY_PASSWORD_SIGNUP_ENABLED", true),
		PasswordResetEnabled:       envBool("GATEWAY_PASSWORD_RESET_ENABLED", true),
		PasswordResetExpirySeconds: envInt("GATEWAY_PASSWORD_RESET_EXPIRY_SECONDS", 900),

		PasswordlessSignupEnabled:       envBool("GATEWAY_PASSWORDLESS_SIGNUP_ENABLED", true),
		PasswordlessCodeTTLSeconds:      envInt("GATEWAY_PASSWORDLESS_CODE_TTL_SECONDS", 300),
		PasswordlessCodeMaxAttempts:     envInt("GATEWAY_PASSWORDLESS_CODE_MAX_ATTEMPTS", 5),
		PasswordlessMagicLinkTTLSeconds: envInt("GATEWAY_PASSWORDLESS_MAGIC_LINK_TTL_SECONDS", 900),

		SMSEnabled:               envBool("GATEWAY_SMS_ENABLED", false),
		SMSProvider:              strings.ToLower(envStr("GATEWAY_SMS_PROVIDER", "")),
		SMSTwilioAccountSID:      envStr("GATEWAY_SMS_TWILIO_ACCOUNT_SID", ""),
		SMSTwilioAuthToken:       envStr("GATEWAY_SMS_TWILIO_AUTH_TOKEN", ""),
		SMSTwilioFrom:            envStr("GATEWAY_SMS_TWILIO_FROM", ""),
		SMSAWSRegion:             envStr("GATEWAY_SMS_AWS_REGION", ""),
		SMSAWSAccessKeyID:        envStr("GATEWAY_SMS_AWS_ACCESS_KEY_ID", ""),
		SMSAWSSecretAccessKey:    envStr("GATEWAY_SMS_AWS_SECRET_ACCESS_KEY", ""),
		SMSAWSSenderID:           envStr("GATEWAY_SMS_AWS_SENDER_ID", ""),
		SMSAzureConnectionString: envStr("GATEWAY_SMS_AZURE_CONNECTION_STRING", ""),
		SMSAzureFrom:             envStr("GATEWAY_SMS_AZURE_FROM", ""),
		PhoneCodeTTLSeconds:      envInt("GATEWAY_PHONE_CODE_TTL_SECONDS", 300),
		PhoneCodeMaxAttempts:     envInt("GATEWAY_PHONE_CODE_MAX_ATTEMPTS", 5),
		PhoneCodeCooldownSeconds: envInt("GATEWAY_PHONE_CODE_COOLDOWN_SECONDS", 60),

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
		PublicEmailDomains: envStr("GATEWAY_PUBLIC_EMAIL_DOMAINS", ""),

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
		// 604800 = 7 days; team invitations are less time-sensitive than
		// password resets.
		TenantInvitationExpirySeconds: envInt("GATEWAY_TENANT_INVITATION_EXPIRY_SECONDS", 604800),
		EmailSendCooldownSeconds:      envInt("GATEWAY_EMAIL_SEND_COOLDOWN_SECONDS", 60),
		SignupEmailCooldownSeconds:    envInt("GATEWAY_SIGNUP_EMAIL_COOLDOWN_SECONDS", 60),
		AuditQueueSize:                envInt("GATEWAY_AUDIT_QUEUE_SIZE", 4096),

		HTTPMaxBodyBytes: int64(envInt("GATEWAY_HTTP_MAX_BODY_BYTES", 1<<20)),

		TrustedProxies: envStr(
			"GATEWAY_TRUSTED_PROXIES",
			"10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32,::1/128",
		),

		RateLimitWindowSeconds:     envInt("GATEWAY_RATE_LIMIT_WINDOW_SECONDS", 60),
		RateLimitSignupPerIP:       envInt("GATEWAY_RATE_LIMIT_SIGNUP_PER_IP", 10),
		RateLimitLoginPerIP:        envInt("GATEWAY_RATE_LIMIT_LOGIN_PER_IP", 30),
		RateLimitResetPerIP:        envInt("GATEWAY_RATE_LIMIT_RESET_PER_IP", 5),
		RateLimitVerifyPerIP:       envInt("GATEWAY_RATE_LIMIT_VERIFY_PER_IP", 20),
		RateLimitPasswordlessPerIP: envInt("GATEWAY_RATE_LIMIT_PASSWORDLESS_PER_IP", 5),
		RateLimitPhonePerIP:        envInt("GATEWAY_RATE_LIMIT_PHONE_PER_IP", 5),

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

// SMS provider names for GATEWAY_SMS_PROVIDER. Firebase/Google are
// intentionally out of scope — those are client-SDK flows, not server
// REST APIs.
const (
	SMSProviderTwilio = "twilio"
	SMSProviderSNS    = "sns"
	SMSProviderAzure  = "azure"
)

// DefaultProjectAuthDomainList returns the configured default-project auth
// domains, lower-cased and de-duplicated, in order — the first entry is the
// primary. Blank entries are dropped; an empty config yields nil.
func (c *Config) DefaultProjectAuthDomainList() []string {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range strings.Split(c.DefaultProjectAuthDomains, ",") {
		h := strings.ToLower(strings.TrimSpace(raw))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// DefaultPrimaryAuthDomain returns the default project's primary serving
// hostname — the first entry of DefaultProjectAuthDomainList — or "" when
// none is configured.
func (c *Config) DefaultPrimaryAuthDomain() string {
	if hosts := c.DefaultProjectAuthDomainList(); len(hosts) > 0 {
		return hosts[0]
	}
	return ""
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

// revocationModeFromEnv reads RevocationMode from the named env var.
// Unrecognised values fall back to def — Load() does not panic so a
// misconfigured env at startup is surfaced by Validate() rather than
// crashing this helper.
func revocationModeFromEnv(key string, def RevocationMode) RevocationMode {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	switch RevocationMode(strings.ToLower(v)) {
	case RevocationModeTTL:
		return RevocationModeTTL
	case RevocationModeSession:
		return RevocationModeSession
	}
	return def
}

// Validate enforces invariants that are too complex to express as
// per-field defaults: most importantly the `mode=ttl` access-token
// TTL ceiling. The binary calls this at startup; tests pin their
// configs through the same path so misuse surfaces immediately
// rather than as a silent revocation-window gap.
//
// Why a method rather than running inside Load(): tests build
// *Config values directly (without going through Load) and a
// silent failure mode there would re-introduce the bug this
// function prevents. Callers that synthesise a Config must invoke
// Validate before handing it to app.New.
func (c *Config) Validate() error {
	switch c.RevocationMode {
	case "":
		// Empty means "use default" in Load(); a directly-constructed
		// Config (e.g. in tests) gets the same treatment so downstream
		// switch statements behave consistently.
		c.RevocationMode = RevocationModeTTL
	case RevocationModeTTL, RevocationModeSession:
	default:
		return fmt.Errorf("config: invalid GATEWAY_REVOCATION_MODE %q (must be one of: ttl, session)", c.RevocationMode)
	}

	if c.RevocationMode == RevocationModeTTL && c.JWTExpirySeconds > RevocationModeTTLAccessTokenCap {
		return fmt.Errorf(
			"config: GATEWAY_JWT_EXPIRY_SECONDS=%d exceeds the %ds cap for GATEWAY_REVOCATION_MODE=ttl; "+
				"set GATEWAY_REVOCATION_MODE=session to keep the longer access-token lifetime",
			c.JWTExpirySeconds, RevocationModeTTLAccessTokenCap,
		)
	}

	if c.SessionCacheTTLSeconds < 0 {
		return fmt.Errorf("config: GATEWAY_SESSION_CACHE_TTL_SECONDS=%d must be >= 0", c.SessionCacheTTLSeconds)
	}

	if err := c.validateSMS(); err != nil {
		return err
	}

	if err := c.validateCaptcha(); err != nil {
		return err
	}

	return nil
}

// validateSMS enforces the SMS-provider invariant: when phone
// verification is enabled, the provider must be one of the supported
// values and its required credentials must be set. Failing closed at
// boot beats a runtime "send to nowhere".
func (c *Config) validateSMS() error {
	if !c.SMSEnabled {
		return nil
	}
	switch c.SMSProvider {
	case SMSProviderTwilio:
		if c.SMSTwilioAccountSID == "" || c.SMSTwilioAuthToken == "" || c.SMSTwilioFrom == "" {
			return errors.New(
				"config: GATEWAY_SMS_PROVIDER=twilio requires GATEWAY_SMS_TWILIO_ACCOUNT_SID, GATEWAY_SMS_TWILIO_AUTH_TOKEN, and GATEWAY_SMS_TWILIO_FROM",
			)
		}
	case SMSProviderSNS:
		if c.SMSAWSRegion == "" || c.SMSAWSAccessKeyID == "" || c.SMSAWSSecretAccessKey == "" {
			return errors.New(
				"config: GATEWAY_SMS_PROVIDER=sns requires GATEWAY_SMS_AWS_REGION, GATEWAY_SMS_AWS_ACCESS_KEY_ID, and GATEWAY_SMS_AWS_SECRET_ACCESS_KEY",
			)
		}
	case SMSProviderAzure:
		if c.SMSAzureConnectionString == "" || c.SMSAzureFrom == "" {
			return errors.New(
				"config: GATEWAY_SMS_PROVIDER=azure requires GATEWAY_SMS_AZURE_CONNECTION_STRING and GATEWAY_SMS_AZURE_FROM",
			)
		}
	default:
		return fmt.Errorf(
			"config: GATEWAY_SMS_ENABLED=true requires GATEWAY_SMS_PROVIDER to be one of %q, %q, %q; got %q",
			SMSProviderTwilio, SMSProviderSNS, SMSProviderAzure, c.SMSProvider,
		)
	}
	return nil
}

// validateCaptcha enforces the CAPTCHA invariants: a deployment that turns
// CAPTCHA on must name a supported provider, supply that provider's secret,
// and (for reCAPTCHA v3) configure a score threshold within [0,1]. A
// disabled deployment is unconstrained — the no-op verifier is wired and
// the provider/secret fields are ignored.
func (c *Config) validateCaptcha() error {
	if !c.CaptchaEnabled {
		return nil
	}

	switch c.CaptchaProvider {
	case CaptchaProviderTurnstile:
		if c.CaptchaTurnstileSecret == "" {
			return fmt.Errorf("config: GATEWAY_CAPTCHA_ENABLED=true with provider %q requires GATEWAY_CAPTCHA_TURNSTILE_SECRET", CaptchaProviderTurnstile)
		}
	case CaptchaProviderRecaptchaV3:
		if c.CaptchaRecaptchaSecret == "" {
			return fmt.Errorf("config: GATEWAY_CAPTCHA_ENABLED=true with provider %q requires GATEWAY_CAPTCHA_RECAPTCHA_SECRET", CaptchaProviderRecaptchaV3)
		}
		if c.CaptchaRecaptchaScoreThreshold < 0 || c.CaptchaRecaptchaScoreThreshold > 1 {
			return fmt.Errorf(
				"config: GATEWAY_CAPTCHA_RECAPTCHA_SCORE_THRESHOLD=%v must be in [0,1]",
				c.CaptchaRecaptchaScoreThreshold,
			)
		}
	default:
		return fmt.Errorf(
			"config: GATEWAY_CAPTCHA_ENABLED=true requires GATEWAY_CAPTCHA_PROVIDER to be one of: %q, %q; got %q",
			CaptchaProviderTurnstile, CaptchaProviderRecaptchaV3, c.CaptchaProvider,
		)
	}

	return nil
}

// SessionCacheTTL returns the configured cache TTL as a time.Duration.
// 0 means strict mode (read on every request).
func (c *Config) SessionCacheTTL() time.Duration {
	return time.Duration(c.SessionCacheTTLSeconds) * time.Second
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
