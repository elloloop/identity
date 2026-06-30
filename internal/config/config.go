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

	// DefaultAgeGateChildMaxAge is the conventional COPPA child boundary:
	// users 12 and under (i.e. under 13) are in the protected CHILD band.
	DefaultAgeGateChildMaxAge = 12
	// DefaultAgeGateAdultAge is the age at or above which a user is an adult;
	// below it (and above child-max) they are a TEEN minor.
	DefaultAgeGateAdultAge = 18
)

// DefaultPostgresConnTimeoutMs is the default per-acquire Postgres connection
// timeout (milliseconds) when GATEWAY_POSTGRES_CONN_TIMEOUT_MS is unset. It
// mirrors pgrepo.DefaultConnTimeout (5s) so the boundary default matches the
// driver's own zero-value fallback.
const DefaultPostgresConnTimeoutMs = 5000

// DefaultProjectIDFallback is the project id used when none is configured.
// It is the env-loader default for GATEWAY_DEFAULT_PROJECT_ID and the value
// app.New normalizes an empty DefaultProjectID to, so a directly-constructed
// Config (tests, embedding callers) never reaches the repo boundary with an
// empty project shard id. The single source of truth for this literal.
const DefaultProjectIDFallback = "default"

// Config holds all identity service configuration.
type Config struct {
	// Server & ports.

	// GRPCPort is the native gRPC listener port (reserved; currently unused).
	GRPCPort int
	// ConnectPort is the Connect-RPC HTTP listener port — the main public RPC surface.
	ConnectPort int
	// MetricsPort is the port serving the Prometheus /metrics endpoint.
	MetricsPort int

	// RepoDriver selects the persistence driver — which Repository / DB
	// implementation the binary wires up: "postgres" (default, the primary
	// datastore), "sqlite" (embedded single-node), or "memory" (in-process,
	// for local dev and tests). Driven by GATEWAY_REPO_DRIVER.
	RepoDriver string

	// DefaultTenantID is the storage-scope (shard) id the default project maps
	// onto — the data-plane tenant zero-config requests are pinned to; distinct
	// from DefaultProjectID. Driven by GATEWAY_DEFAULT_TENANT_ID.
	DefaultTenantID string

	// DefaultProjectID is the id of the control-plane Project the service
	// seeds on boot (postgres driver) and pins zero-config requests to. It
	// is a logical control-plane entity that MAPS ONTO the storage scope
	// DefaultTenantID — the two are distinct values and must not be
	// conflated. Driven by GATEWAY_DEFAULT_PROJECT_ID (default "default").
	// Only the postgres driver has a control plane; the memory driver ignores it.
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
	// has a control plane; the memory driver ignores it.
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

	// RequireVerifiedAuthDomain governs whether an UNVERIFIED custom
	// auth-domain marked is_primary may become a project's primary
	// auth-domain — the host that drives branded link URLs (magic links,
	// invitations) and cookie domains. When true (the safe default), the
	// primary-auth-domain selection requires verified_at_ms > 0, so only a
	// DNS-verified host can drive branded links, matching the verified-only
	// Host→project resolver and the proto contract on is_primary. identity
	// is a library/OSS server, so whether to trust an unverified is_primary
	// host is the deployer's policy: set this false to opt in. Driven by
	// GATEWAY_REQUIRE_VERIFIED_AUTH_DOMAIN, default true.
	RequireVerifiedAuthDomain bool

	// Email service (internal gRPC).

	// EmailServiceHost is the host of the internal email-sending gRPC service.
	EmailServiceHost string
	// EmailServicePort is the port of the internal email-sending gRPC service.
	EmailServicePort int

	// JWT (RS256). Two signer backends ship in-tree (file, kms_aws); adding a
	// new one (GCP KMS, HashiCorp Vault, hardware HSM, …) is a matter of
	// implementing pkg/jwt.Signer in a sibling package.

	// JWTSigner selects the JWT signing backend: "file" (default, RS256 keys
	// read from JWTKeysFile, reloaded on SIGHUP) or "kms_aws" (AWS KMS).
	JWTSigner string
	// JWTKeysFile is the path to the RS256 key document read by the "file"
	// signer; empty auto-generates a throwaway dev key at startup (local dev /
	// CI only — emits a warning log).
	JWTKeysFile string
	// JWTKMSKeys is a CSV of "kid=keyARN" entries for the "kms_aws" signer;
	// required when GATEWAY_JWT_SIGNER=kms_aws.
	JWTKMSKeys string
	// JWTKMSAWSRegion is the AWS region for the "kms_aws" signer.
	JWTKMSAWSRegion string
	// JWTExpirySeconds is the access-token (JWT) lifetime in seconds; capped at
	// 900 (RevocationModeTTLAccessTokenCap) under revocation mode "ttl".
	JWTExpirySeconds int

	// JWTAudience, when non-empty, is stamped on minted access tokens as the
	// "aud" claim and enforced by the verifier on every request.
	JWTAudience string
	// JWTRequireAudience, when true, also rejects tokens that carry no "aud"
	// claim; the false default lets a deploy roll out the mint-side change
	// first, wait for in-flight tokens to expire, then flip to required.
	JWTRequireAudience bool

	// RefreshExpirySeconds is the refresh-token lifetime in seconds (default 7 days).
	RefreshExpirySeconds int

	// RevocationMode selects how a DeleteRefreshTokensForUser propagates to
	// in-flight access tokens — "ttl" (default) or "session".
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

	// ProjectResolutionCacheTTLSeconds bounds how long a per-request
	// project resolution (credential-key→project and Host→project) may be
	// served from the in-process cache before being re-read from the
	// control-plane store. Project resolution runs ahead of the rate
	// limiter and on every CORS preflight, so caching it removes 2-3
	// uncached DB queries from the hot path. Kept short so a suspended
	// project or revoked credential is never served stale beyond the TTL.
	// 0 = disabled: every request resolves against the store.
	ProjectResolutionCacheTTLSeconds int

	// ProjectResolutionCacheMaxEntries bounds the number of distinct
	// resolution keys (credential ids + hostnames) held in the cache,
	// evicting the least-recently-used entry past the bound so the cache
	// cannot grow unbounded under hostile or high-cardinality traffic.
	ProjectResolutionCacheMaxEntries int

	// OAuth providers. Identity does the code exchange itself (see pkg/oauth);
	// a provider is enabled only when BOTH its ID and secret are non-empty.

	// GoogleClientID is the Google OAuth client ID.
	GoogleClientID string
	// GoogleClientSecret is the Google OAuth client secret.
	GoogleClientSecret string
	// GoogleAuthorizationURL overrides the Google OAuth authorization endpoint; empty = the real Google endpoint. For self-hosted proxies and end-to-end tests against a mock OIDC provider.
	GoogleAuthorizationURL string
	// GoogleTokenURL overrides the Google OAuth token endpoint; empty = the real Google endpoint.
	GoogleTokenURL string
	// GoogleJWKSURL overrides the Google OIDC JWKS (public keys) endpoint; empty = the real Google endpoint.
	GoogleJWKSURL string
	// GoogleDiscoveryURL overrides the Google OIDC discovery document URL; empty = the real Google endpoint. When set, the authorization / token / JWKS / userinfo endpoints are resolved from this document.
	GoogleDiscoveryURL string
	// GoogleUserinfoURL overrides the Google OIDC userinfo endpoint; empty = the real Google endpoint.
	GoogleUserinfoURL string
	// GoogleIssuer overrides the expected Google OIDC token issuer; empty = the real Google issuer.
	GoogleIssuer string
	// MicrosoftClientID is the Microsoft / Entra ID OAuth client ID.
	MicrosoftClientID string
	// MicrosoftClientSecret is the Microsoft / Entra ID OAuth client secret.
	MicrosoftClientSecret string
	// MicrosoftTenantID is the Microsoft directory (tenant) id, or "common" for multi-tenant.
	MicrosoftTenantID string
	// GitHubClientID is the GitHub OAuth client ID.
	GitHubClientID string
	// GitHubClientSecret is the GitHub OAuth client secret.
	GitHubClientSecret string
	// AppleClientID is the Apple Service ID used as the OAuth client ID.
	AppleClientID string
	// AppleTeamID is the Apple Developer Team ID.
	AppleTeamID string
	// AppleKeyID is the Apple private-key (Key) ID.
	AppleKeyID string
	// ApplePrivateKey is the Apple Sign in private key (PEM or base64).
	ApplePrivateKey string

	// OAuthAllowedReturnURLs is the comma-separated allowlist of app URLs
	// the hosted OAuth flow may redirect back to (the `return_to` param of
	// GET /oauth/start/{provider}). Each entry is an exact origin or a path
	// prefix. A return_to must match the configured origin and, for path
	// entries, the configured path or one of its descendants. Validation is
	// fail-closed: a return_to that matches no entry is rejected with 400.
	//
	// Empty disables the hosted flow entirely — GET /oauth/start and
	// GET/POST /oauth/callback return 404. The headless BeginOAuthLogin / OAuthLogin
	// RPCs are unaffected. Driven by GATEWAY_OAUTH_ALLOWED_RETURN_URLS.
	OAuthAllowedReturnURLs string

	// Identity verification (document + selfie); the provider selects the
	// implementation in pkg/idv.

	// IDVProvider selects the IDV backend — "azure", "stub", or "" (disabled;
	// the IDV RPCs return CodeUnimplemented).
	IDVProvider string
	// IDVAzureEndpoint is the Azure Cognitive Services Face endpoint URL for
	// the azure provider (e.g. https://NAME.cognitiveservices.azure.com).
	IDVAzureEndpoint string
	// IDVAzureKey is the Azure Cognitive Services API key (azure provider).
	IDVAzureKey string
	// IDVAzureSessionTTLSec is the IDV session-token lifetime in seconds.
	IDVAzureSessionTTLSec int
	// When true, PasswordLogin / OAuthLogin reject users without an
	// approved identity verification. The default is false (verification
	// is offered but not required) to match the existing email-verified
	// pattern. Tenants that need stricter onboarding flip this on.
	IDVRequired bool

	// CAPTCHA verification on unauthenticated endpoints. When disabled the
	// no-op verifier is wired and the per-endpoint toggles are ignored; the
	// toggles default true, so enabling CAPTCHA gates every endpoint unless one
	// is flipped off.

	// CaptchaEnabled is the global on/off for CAPTCHA on unauthenticated endpoints.
	CaptchaEnabled bool
	// CaptchaProvider selects the pkg/captcha implementation — "turnstile" or
	// "recaptcha_v3"; the matching secret must be set.
	CaptchaProvider string
	// CaptchaTurnstileSecret is the Cloudflare Turnstile secret key (provider "turnstile").
	CaptchaTurnstileSecret string
	// CaptchaRecaptchaSecret is the reCAPTCHA v3 secret key (provider "recaptcha_v3").
	CaptchaRecaptchaSecret string
	// CaptchaRecaptchaScoreThreshold is the reCAPTCHA v3 score below which a
	// response is rejected; must be in [0,1].
	CaptchaRecaptchaScoreThreshold float64
	// CaptchaEnforcePasswordSignup gates CAPTCHA on the PasswordSignup endpoint.
	CaptchaEnforcePasswordSignup bool
	// CaptchaEnforcePasswordLogin gates CAPTCHA on the PasswordLogin endpoint.
	CaptchaEnforcePasswordLogin bool
	// CaptchaEnforcePasswordReset gates CAPTCHA on the RequestPasswordReset endpoint.
	CaptchaEnforcePasswordReset bool
	// CaptchaEnforceEmailLoginCode gates CAPTCHA on the RequestEmailLoginCode endpoint.
	CaptchaEnforceEmailLoginCode bool
	// CaptchaEnforceMagicLink gates CAPTCHA on the RequestMagicLink endpoint.
	CaptchaEnforceMagicLink bool

	// Age-gating (COPPA). When disabled the no-op determiner is wired (everyone
	// classifies as adult, no consent gating) and signup behaves as before.

	// AgeGateEnabled is the global on/off for age-gating.
	AgeGateEnabled bool
	// AgeGateChildMaxAge is the inclusive upper age of the protected CHILD band
	// (default 12 → under-13).
	AgeGateChildMaxAge int
	// AgeGateAdultAge is the age at or above which a user is an adult; between it
	// and AgeGateChildMaxAge a user is a TEEN minor (default 18).
	AgeGateAdultAge int
	// AgeGateRequireDOB rejects a signup that omits a date of birth
	// (INVALID_ARGUMENT) instead of treating it as adult.
	AgeGateRequireDOB bool

	// MinorDataMinimization gates COPPA-style data-minimization for accounts
	// the age gate classifies as AGE_BAND_CHILD. When true (and the age gate
	// is enabled), the server refuses to collect or persist non-essential PII
	// from a child: RequestPhoneVerification and BeginIdentityVerification are
	// rejected with ErrMinorDataMinimized, and a recovery_email / avatar_url
	// supplied for a child at signup or profile-update is dropped rather than
	// stored. Default false preserves today's behavior — adults, teens, and
	// accounts with an unknown age band are never affected.
	MinorDataMinimization bool // GATEWAY_MINOR_DATA_MINIMIZATION (default false)

	// Password.

	// PasswordSignupEnabled gates self-serve PasswordSignup; set false to
	// disable it (admin-driven invitations still work).
	PasswordSignupEnabled bool
	// PasswordResetEnabled gates RequestPasswordReset; when false the RPC stays
	// enumeration-safe but is a no-op (admin resets still work).
	PasswordResetEnabled bool
	// PasswordResetExpirySeconds is the recovery-email reset-link lifetime in seconds.
	PasswordResetExpirySeconds int

	// Passwordless email login (OTP code + magic link).

	// PasswordlessSignupEnabled gates auto-create on a passwordless verify for
	// an unknown email: when false the unknown email gets the same
	// anti-enumeration decoy as a known one, so the endpoint never reveals which
	// addresses exist. Mirrors PasswordSignupEnabled.
	PasswordlessSignupEnabled bool
	// PasswordlessCodeTTLSeconds is the one-time-code lifetime in seconds (code length is fixed at 6 digits).
	PasswordlessCodeTTLSeconds int
	// PasswordlessCodeMaxAttempts is the max verify attempts per OTP before it
	// is invalidated (brute-force cap).
	PasswordlessCodeMaxAttempts int
	// PasswordlessMagicLinkTTLSeconds is the magic-link token lifetime in seconds.
	PasswordlessMagicLinkTTLSeconds int

	// Phone verification (SMS OTP) — standalone phone-ownership verification for
	// an already-authenticated user, not yet a login factor. When SMSEnabled, a
	// provider and its credentials must be set (enforced by Validate).

	// SMSEnabled turns on phone (SMS OTP) verification.
	SMSEnabled bool
	// SMSProvider selects the SMS backend: "twilio", "sns", or "azure".
	SMSProvider string

	// SMSTwilioAccountSID is the Twilio Account SID (provider "twilio").
	SMSTwilioAccountSID string
	// SMSTwilioAuthToken is the Twilio auth token (provider "twilio").
	SMSTwilioAuthToken string
	// SMSTwilioFrom is the Twilio sender phone number (provider "twilio").
	SMSTwilioFrom string

	// SMSAWSRegion is the AWS region for the SNS sender (provider "sns").
	SMSAWSRegion string
	// SMSAWSAccessKeyID is the AWS access key id for SNS (provider "sns").
	SMSAWSAccessKeyID string
	// SMSAWSSecretAccessKey is the AWS secret access key for SNS (provider "sns").
	SMSAWSSecretAccessKey string
	// SMSAWSSenderID is the optional AWS SNS sender id (provider "sns").
	SMSAWSSenderID string

	// SMSAzureConnectionString is the Azure Communication Services connection
	// string (provider "azure").
	SMSAzureConnectionString string
	// SMSAzureFrom is the Azure Communication Services sender number (provider "azure").
	SMSAzureFrom string

	// PhoneCodeTTLSeconds is the phone-verification OTP lifetime in seconds.
	PhoneCodeTTLSeconds int
	// PhoneCodeMaxAttempts is the max wrong-code guesses before the OTP is invalidated.
	PhoneCodeMaxAttempts int
	// PhoneCodeCooldownSeconds is the per-request cooldown (seconds) between phone-verification sends.
	PhoneCodeCooldownSeconds int

	// TOTP (2FA).

	// TOTPEncryptionKey is the base64-encoded 32-byte AES-256 key that encrypts
	// TOTP secrets at rest. Throwaway dev key if unset; required in prod (a
	// deterministic dev fallback must never be used in production).
	TOTPEncryptionKey string
	// TOTPIssuer is the issuer name shown in users' authenticator apps.
	TOTPIssuer string

	// Pepper used as the HMAC-SHA-256 key for recovery-code hashing.
	// Base64-encoded; must decode to >= 32 bytes. Required whenever
	// TOTPEncryptionKey is set (i.e. any non-dev deployment). The
	// pepper turns a stolen DB into a brute-force-resistant artifact:
	// without it, an attacker cannot precompute or enumerate hashes.
	TOTPRecoveryPepper string

	// LoginChallengeExpirySeconds is the window (seconds) after a password
	// success in which the user must complete the 2FA challenge.
	LoginChallengeExpirySeconds int

	// WebAuthn / Passkeys.

	// PasskeyRPID is the WebAuthn relying-party ID — must match the registrable
	// domain (e.g. example.com).
	PasskeyRPID string
	// PasskeyRPName is the human-readable WebAuthn relying-party name.
	PasskeyRPName string
	// PasskeyOrigin is the allowed origin for passkey ceremonies (scheme + host + port).
	PasskeyOrigin string
	// PasskeyChallengeExpirySeconds is the lifetime in seconds of registration / login challenges.
	PasskeyChallengeExpirySeconds int
	// PasskeySignupEnabled gates passkey-first signup (the unauthenticated
	// BeginPasskeySignup / CompletePasskeySignup pair that creates a brand-new
	// account from a passkey); set false to disable it while leaving
	// authenticated add-a-passkey registration untouched.
	PasskeySignupEnabled bool

	// QR login (cross-device authorization).

	// QRLoginBaseURL is the base URL embedded in the cross-device login QR code.
	QRLoginBaseURL string
	// QRLoginExpirySeconds is the QR login-session lifetime in seconds.
	QRLoginExpirySeconds int

	// Login security (failed-login lockout).

	// LoginMaxFailedAttempts is the consecutive failed-login count that triggers a lockout.
	LoginMaxFailedAttempts int
	// LoginLockoutSeconds is how long (seconds) an account stays locked after the threshold is hit.
	LoginLockoutSeconds int

	// DefaultEmailDomain is the default email domain applied to new accounts.
	DefaultEmailDomain string

	// PublicEmailDomains extends the built-in set of consumer/public email
	// providers (gmail, outlook, yahoo, …) used by IsPublicEmailDomain. A
	// verified email under a public domain does NOT imply company
	// affiliation, so a tenant is never auto-formed from one. Comma-
	// separated; entries are punycode-canonicalised. Driven by
	// GATEWAY_PUBLIC_EMAIL_DOMAINS (default empty — the built-in set
	// already covers the major global providers).
	PublicEmailDomains string

	// AllowedOrigins is the comma-separated list of CORS allowed origins.
	AllowedOrigins string

	// Cookie settings.

	// CookieDomain is the Domain attribute set on auth cookies (empty = host-only).
	CookieDomain string
	// CookieSecure sets the Secure attribute on auth cookies; enable in prod (HTTPS-only).
	CookieSecure bool
	// CookieSameSite is the SameSite attribute on auth cookies — "Lax", "Strict", or "None".
	CookieSameSite string

	// AuthAllowLocal enables local username/password auth; set false to require
	// OAuth (intended for development).
	AuthAllowLocal bool

	// AuthRequireVerifiedEmail blocks authentication until the account's email
	// is verified. Default ON. Closes an account pre-hijacking vector: an
	// attacker who plants a password account for an unverified address cannot
	// use it, and a session is never issued for an unverified account.
	AuthRequireVerifiedEmail bool

	// SMTP single-provider config (simple form); SMTPProviders, if set, takes precedence.

	// SMTPHost is the SMTP server hostname.
	SMTPHost string
	// SMTPPort is the SMTP server port.
	SMTPPort int
	// SMTPUser is the SMTP auth username.
	SMTPUser string
	// SMTPPass is the SMTP auth password.
	SMTPPass string
	// SMTPFrom is the envelope/From address for outbound mail.
	SMTPFrom string
	// SMTPTLS enables STARTTLS / TLS for the SMTP connection.
	SMTPTLS bool

	// SMTPProviders is a JSON array of SMTP configs ([]email.SMTPConfig) used as
	// a failover chain in order; overrides the single-provider SMTP_* vars.
	SMTPProviders string

	// Email branding defaults — the global fallback for the per-project branding
	// block (config_json branding.*); when both are empty, mail falls back to
	// the byte-compatible unbranded output. One server serving two products
	// overrides these per project.

	// EmailBrandProductName is the product name shown in email bodies.
	EmailBrandProductName string
	// EmailBrandFrom is the From address for transactional mail (falls back to SMTPFrom).
	EmailBrandFrom string
	// EmailBrandFromName is the From display name (rendered as "Name" <addr>).
	EmailBrandFromName string
	// EmailBrandLogoURL is the absolute https logo URL shown in HTML email.
	EmailBrandLogoURL string
	// EmailBrandPrimaryColor is the CSS colour used to tint branded HTML email.
	EmailBrandPrimaryColor string
	// EmailBrandSupportEmail is the support address shown in footers and set as the Reply-To header.
	EmailBrandSupportEmail string
	// EmailListUnsubscribe is the List-Unsubscribe header value applied to
	// configured mail (e.g. "<mailto:unsubscribe@example.com>"). Empty omits the
	// header; auth/transactional mail stays deliverable either way.
	EmailListUnsubscribe string

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
	// auth hot path produces events faster than the datastore can absorb them.
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

	// Rate-limit configuration. The in-memory token bucket is keyed by client
	// IP; quotas are requests per window per IP. Set a quota to 0 to disable
	// that per-endpoint limiter.

	// RateLimitWindowSeconds is the sliding window length (seconds) for the per-IP limiter.
	RateLimitWindowSeconds int
	// RateLimitSignupPerIP is the per-IP request cap per window on PasswordSignup.
	RateLimitSignupPerIP int
	// RateLimitLoginPerIP is the per-IP request cap per window on the login endpoints.
	RateLimitLoginPerIP int
	// RateLimitResetPerIP is the per-IP request cap per window on RequestPasswordReset.
	RateLimitResetPerIP int
	// RateLimitVerifyPerIP is the per-IP request cap per window on the verification endpoints.
	RateLimitVerifyPerIP int
	// RateLimitPasswordlessPerIP is the per-IP cap per window on
	// RequestEmailLoginCode + RequestMagicLink.
	RateLimitPasswordlessPerIP int
	// RateLimitPhonePerIP is the per-IP cap per window on RequestPhoneVerification.
	RateLimitPhonePerIP int
	// RateLimitBootstrapPerIP is the per-IP cap per window on CreateFirstPlatformAdmin.
	RateLimitBootstrapPerIP int

	// Postgres (the primary persistence driver).

	// PostgresDSN is the Postgres connection string (e.g.
	// "postgres://user:pass@host:5432/identity?sslmode=disable"); required when
	// RepoDriver is "postgres" (the default).
	PostgresDSN string
	// PostgresMaxConns is the connection-pool size.
	PostgresMaxConns int
	// PostgresConnTimeoutMs is the per-acquire connection timeout in
	// milliseconds, applied when checking a connection out of the pgx pool
	// (pgxpool ConnectTimeout). It bounds how long a connect/acquire may block,
	// not total query time — callers still pass a context deadline. Default 5000.
	PostgresConnTimeoutMs int
	// PostgresAutoMigrate runs pending migrations on connect; leave false in
	// production and run migrations out-of-band (a rolling deploy can race replicas).
	PostgresAutoMigrate bool

	// SQLite (lightweight embedded / single-node persistence driver), selected
	// with GATEWAY_REPO_DRIVER=sqlite — pure-Go modernc.org/sqlite, no cgo.

	// SQLitePath is the SQLite database file path, or ":memory:" for an
	// ephemeral in-process database; required when RepoDriver is "sqlite".
	SQLitePath string
	// SQLiteMaxConns is the connection-pool size for a file database.
	SQLiteMaxConns int

	// OpenTelemetry tracing to a deployer-supplied OTLP collector. Default off
	// (no-op tracer, interceptor omitted) so a deployer with no collector pays
	// zero cost.

	// OTelEnabled turns on OTLP trace export.
	OTelEnabled bool
	// OTelExporterEndpoint is the OTLP collector host:port; required when OTelEnabled.
	OTelExporterEndpoint string
	// OTelExporterProtocol is the OTLP transport — "grpc" or "http".
	OTelExporterProtocol string
	// OTelSampleRatio is the trace head-sampling ratio in [0.0, 1.0].
	OTelSampleRatio float64
	// OTelDeploymentEnv sets the deployment.environment.name resource attribute.
	OTelDeploymentEnv string
	// OTelServiceVersion overrides the build version baked into the binary on emitted traces.
	OTelServiceVersion string

	// Sweeper (#94) — a background goroutine that periodically deletes
	// expired-but-uncollected rows from the ephemeral tables (WebAuthn
	// challenges, email-verification / password-reset / email-change tokens,
	// login challenges) that would otherwise grow unboundedly.

	// SweeperIntervalSeconds is the sweep tick interval in seconds; 0 disables
	// sweeping entirely (for tests or deployers who run their own GC).
	SweeperIntervalSeconds int
	// SweeperBatchSize is the per-table, per-tick deletion cap.
	SweeperBatchSize int
	// SweeperGraceSeconds is extra grace past expires_at before a row is
	// eligible for deletion (covers flows that just consumed the token).
	SweeperGraceSeconds int

	// Outbound webhooks / user-lifecycle eventing (#261). When disabled
	// (the default), the service emits events to a no-op publisher: there is
	// no observable behaviour change and no background worker runs. When
	// enabled, user create/update/deactivate events are fanned out to
	// per-tenant subscriptions and delivered as signed webhooks
	// at-least-once, with retry/backoff recorded in a transactional outbox.

	// WebhooksEnabled is the master switch for outbound user-lifecycle
	// eventing; when false the service emits to a no-op publisher and runs no
	// delivery worker. Driven by GATEWAY_WEBHOOKS_ENABLED (default false).
	WebhooksEnabled bool
	// WebhooksMaxAttempts is the per-delivery retry budget before a webhook is
	// abandoned and surfaced via the structured logger. Driven by
	// GATEWAY_WEBHOOKS_MAX_ATTEMPTS (default 6).
	WebhooksMaxAttempts int
	// WebhooksBackoffBaseSeconds is the first-retry delay; it doubles per
	// attempt up to the ceiling. Driven by GATEWAY_WEBHOOKS_BACKOFF_BASE_SECONDS
	// (default 2).
	WebhooksBackoffBaseSeconds int
	// WebhooksBackoffMaxSeconds is the exponential-backoff ceiling. Driven by
	// GATEWAY_WEBHOOKS_BACKOFF_MAX_SECONDS (default 300).
	WebhooksBackoffMaxSeconds int
	// WebhooksWorkerIntervalSeconds is the outbox drain tick interval. Driven
	// by GATEWAY_WEBHOOKS_WORKER_INTERVAL_SECONDS (default 1).
	WebhooksWorkerIntervalSeconds int
	// WebhooksBatchSize is the number of due deliveries claimed per tick.
	// Driven by GATEWAY_WEBHOOKS_BATCH_SIZE (default 50).
	WebhooksBatchSize int
}

// Load reads configuration from environment variables with GATEWAY_
// prefix, falling back to sensible defaults for local development.
func Load() *Config {
	return &Config{
		GRPCPort:    envInt("GATEWAY_GRPC_PORT", 50051),
		ConnectPort: envInt("GATEWAY_CONNECT_PORT", 80),
		MetricsPort: envInt("GATEWAY_METRICS_PORT", 9090),

		RepoDriver: envStr("GATEWAY_REPO_DRIVER", "postgres"),

		DefaultTenantID:           envStr("GATEWAY_DEFAULT_TENANT_ID", "local"),
		DefaultProjectID:          envStr("GATEWAY_DEFAULT_PROJECT_ID", DefaultProjectIDFallback),
		AdminAPISecret:            envStr("GATEWAY_ADMIN_API_SECRET", ""),
		DefaultProjectAuthDomains: envStr("GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS", ""),
		RequireVerifiedAuthDomain: envBool("GATEWAY_REQUIRE_VERIFIED_AUTH_DOMAIN", true),

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

		ProjectResolutionCacheTTLSeconds: envInt("GATEWAY_PROJECT_RESOLUTION_CACHE_TTL_SECONDS", 30),
		ProjectResolutionCacheMaxEntries: envInt("GATEWAY_PROJECT_RESOLUTION_CACHE_MAX_ENTRIES", 10000),

		GoogleClientID:         envStr("GATEWAY_OAUTH_GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:     envStr("GATEWAY_OAUTH_GOOGLE_CLIENT_SECRET", ""),
		GoogleAuthorizationURL: envStr("GATEWAY_OAUTH_GOOGLE_AUTHORIZATION_URL", ""),
		GoogleTokenURL:         envStr("GATEWAY_OAUTH_GOOGLE_TOKEN_URL", ""),
		GoogleJWKSURL:          envStr("GATEWAY_OAUTH_GOOGLE_JWKS_URL", ""),
		GoogleDiscoveryURL:     envStr("GATEWAY_OAUTH_GOOGLE_DISCOVERY_URL", ""),
		GoogleUserinfoURL:      envStr("GATEWAY_OAUTH_GOOGLE_USERINFO_URL", ""),
		GoogleIssuer:           envStr("GATEWAY_OAUTH_GOOGLE_ISSUER", ""),
		MicrosoftClientID:      envStr("GATEWAY_OAUTH_MICROSOFT_CLIENT_ID", ""),
		MicrosoftClientSecret:  envStr("GATEWAY_OAUTH_MICROSOFT_CLIENT_SECRET", ""),
		MicrosoftTenantID:      envStr("GATEWAY_MICROSOFT_TENANT_ID", ""),
		GitHubClientID:         envStr("GATEWAY_OAUTH_GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:     envStr("GATEWAY_OAUTH_GITHUB_CLIENT_SECRET", ""),
		AppleClientID:          envStr("GATEWAY_OAUTH_APPLE_CLIENT_ID", ""),
		AppleTeamID:            envStr("GATEWAY_OAUTH_APPLE_TEAM_ID", ""),
		AppleKeyID:             envStr("GATEWAY_OAUTH_APPLE_KEY_ID", ""),
		ApplePrivateKey:        envStr("GATEWAY_OAUTH_APPLE_PRIVATE_KEY", ""),

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

		AgeGateEnabled:     envBool("GATEWAY_AGEGATE_ENABLED", false),
		AgeGateChildMaxAge: envInt("GATEWAY_AGEGATE_CHILD_MAX_AGE", DefaultAgeGateChildMaxAge),
		AgeGateAdultAge:    envInt("GATEWAY_AGEGATE_ADULT_AGE", DefaultAgeGateAdultAge),
		AgeGateRequireDOB:  envBool("GATEWAY_AGEGATE_REQUIRE_DOB", false),

		MinorDataMinimization: envBool("GATEWAY_MINOR_DATA_MINIMIZATION", false),

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
		PasskeySignupEnabled:          envBool("GATEWAY_PASSKEY_SIGNUP_ENABLED", true),

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

		AuthAllowLocal:           envBool("GATEWAY_AUTH_ALLOW_LOCAL", true),
		AuthRequireVerifiedEmail: envBool("GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL", true),

		SMTPHost:      envStr("GATEWAY_SMTP_HOST", ""),
		SMTPPort:      envInt("GATEWAY_SMTP_PORT", 587),
		SMTPUser:      envStr("GATEWAY_SMTP_USER", ""),
		SMTPPass:      envStr("GATEWAY_SMTP_PASS", ""),
		SMTPFrom:      envStr("GATEWAY_SMTP_FROM", ""),
		SMTPTLS:       envBool("GATEWAY_SMTP_TLS", true),
		SMTPProviders: envStr("GATEWAY_SMTP_PROVIDERS", ""),

		EmailBrandProductName:  envStr("GATEWAY_EMAIL_BRAND_PRODUCT_NAME", ""),
		EmailBrandFrom:         envStr("GATEWAY_EMAIL_BRAND_FROM", ""),
		EmailBrandFromName:     envStr("GATEWAY_EMAIL_BRAND_FROM_NAME", ""),
		EmailBrandLogoURL:      envStr("GATEWAY_EMAIL_BRAND_LOGO_URL", ""),
		EmailBrandPrimaryColor: envStr("GATEWAY_EMAIL_BRAND_PRIMARY_COLOR", ""),
		EmailBrandSupportEmail: envStr("GATEWAY_EMAIL_BRAND_SUPPORT_EMAIL", ""),
		EmailListUnsubscribe:   envStr("GATEWAY_EMAIL_LIST_UNSUBSCRIBE", ""),

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
		RateLimitBootstrapPerIP:    envInt("GATEWAY_RATE_LIMIT_BOOTSTRAP_PER_IP", 5),

		PostgresDSN:           envStr("GATEWAY_POSTGRES_DSN", ""),
		PostgresMaxConns:      envInt("GATEWAY_POSTGRES_MAX_CONNS", 25),
		PostgresConnTimeoutMs: envInt("GATEWAY_POSTGRES_CONN_TIMEOUT_MS", DefaultPostgresConnTimeoutMs),
		PostgresAutoMigrate:   envBool("GATEWAY_POSTGRES_AUTO_MIGRATE", false),

		SQLitePath:     envStr("GATEWAY_SQLITE_PATH", ""),
		SQLiteMaxConns: envInt("GATEWAY_SQLITE_MAX_CONNS", 4),

		OTelEnabled:          envBool("GATEWAY_OTEL_ENABLED", false),
		OTelExporterEndpoint: envStr("GATEWAY_OTEL_EXPORTER_ENDPOINT", ""),
		OTelExporterProtocol: envStr("GATEWAY_OTEL_EXPORTER_PROTOCOL", "grpc"),
		OTelSampleRatio:      envFloat("GATEWAY_OTEL_SAMPLE_RATIO", 0.1),
		OTelDeploymentEnv:    envStr("GATEWAY_OTEL_DEPLOYMENT_ENV", ""),
		OTelServiceVersion:   envStr("GATEWAY_OTEL_SERVICE_VERSION", ""),

		SweeperIntervalSeconds: envInt("GATEWAY_SWEEPER_INTERVAL_SECONDS", 300),
		SweeperBatchSize:       envInt("GATEWAY_SWEEPER_BATCH_SIZE", 500),
		SweeperGraceSeconds:    envInt("GATEWAY_SWEEPER_GRACE_SECONDS", 60),

		WebhooksEnabled:               envBool("GATEWAY_WEBHOOKS_ENABLED", false),
		WebhooksMaxAttempts:           envInt("GATEWAY_WEBHOOKS_MAX_ATTEMPTS", 6),
		WebhooksBackoffBaseSeconds:    envInt("GATEWAY_WEBHOOKS_BACKOFF_BASE_SECONDS", 2),
		WebhooksBackoffMaxSeconds:     envInt("GATEWAY_WEBHOOKS_BACKOFF_MAX_SECONDS", 300),
		WebhooksWorkerIntervalSeconds: envInt("GATEWAY_WEBHOOKS_WORKER_INTERVAL_SECONDS", 1),
		WebhooksBatchSize:             envInt("GATEWAY_WEBHOOKS_BATCH_SIZE", 50),
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

	if err := c.validateWebhooks(); err != nil {
		return err
	}

	if err := c.validateAgeGate(); err != nil {
		return err
	}

	return nil
}

// validateWebhooks enforces the outbound-eventing invariants: the retry
// and backoff knobs must be positive and the cap must not be smaller than
// the base. The checks only run when eventing is enabled — a disabled
// deployment uses a no-op publisher and runs no worker, so its (unused)
// knobs are irrelevant.
func (c *Config) validateWebhooks() error {
	if !c.WebhooksEnabled {
		return nil
	}
	if c.WebhooksMaxAttempts < 1 {
		return fmt.Errorf("config: GATEWAY_WEBHOOKS_MAX_ATTEMPTS=%d must be >= 1", c.WebhooksMaxAttempts)
	}
	if c.WebhooksBackoffBaseSeconds < 1 {
		return fmt.Errorf("config: GATEWAY_WEBHOOKS_BACKOFF_BASE_SECONDS=%d must be >= 1", c.WebhooksBackoffBaseSeconds)
	}
	if c.WebhooksBackoffMaxSeconds < c.WebhooksBackoffBaseSeconds {
		return fmt.Errorf(
			"config: GATEWAY_WEBHOOKS_BACKOFF_MAX_SECONDS=%d must be >= GATEWAY_WEBHOOKS_BACKOFF_BASE_SECONDS=%d",
			c.WebhooksBackoffMaxSeconds, c.WebhooksBackoffBaseSeconds,
		)
	}
	if c.WebhooksWorkerIntervalSeconds < 1 {
		return fmt.Errorf("config: GATEWAY_WEBHOOKS_WORKER_INTERVAL_SECONDS=%d must be >= 1", c.WebhooksWorkerIntervalSeconds)
	}
	if c.WebhooksBatchSize < 1 {
		return fmt.Errorf("config: GATEWAY_WEBHOOKS_BATCH_SIZE=%d must be >= 1", c.WebhooksBatchSize)
	}
	return nil
}

// validateAgeGate enforces the age-gate invariant: when age-gating is on the
// two boundaries must satisfy 0 <= child-max < adult. A disabled deployment
// is unconstrained — the no-op determiner is wired and the thresholds are
// ignored.
func (c *Config) validateAgeGate() error {
	if !c.AgeGateEnabled {
		return nil
	}
	if c.AgeGateChildMaxAge < 0 {
		return fmt.Errorf("config: GATEWAY_AGEGATE_CHILD_MAX_AGE=%d must be >= 0", c.AgeGateChildMaxAge)
	}
	if c.AgeGateAdultAge <= c.AgeGateChildMaxAge {
		return fmt.Errorf(
			"config: GATEWAY_AGEGATE_ADULT_AGE=%d must be greater than GATEWAY_AGEGATE_CHILD_MAX_AGE=%d",
			c.AgeGateAdultAge, c.AgeGateChildMaxAge,
		)
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

// ProjectResolutionCacheTTL returns the configured project-resolution cache
// TTL as a time.Duration. 0 means disabled (resolve on every request).
func (c *Config) ProjectResolutionCacheTTL() time.Duration {
	return time.Duration(c.ProjectResolutionCacheTTLSeconds) * time.Second
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
