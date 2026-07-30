// Package config loads the identity service configuration from
// environment variables with the GATEWAY_ prefix.
//
// This is the Go port of backend/api_gateway/config.py. It uses
// os.Getenv with typed defaults — no external config library needed.
// Sensitive values (secrets, encryption keys, client secrets) are
// never logged.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
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

// Web-assurance provider names accepted in GATEWAY_ASSURANCE_WEB_PROVIDER.
// They mirror the assurance.Provider* constants; config validates against
// these without importing pkg/assurance (config has no dependencies on the
// service tree).
const (
	AssuranceWebProviderTurnstile   = "turnstile"
	AssuranceWebProviderRecaptchaV3 = "recaptcha_v3"

	// DefaultAssuranceRecaptchaScoreThreshold is the reCAPTCHA v3 score below
	// which a response is rejected when no threshold is configured.
	DefaultAssuranceRecaptchaScoreThreshold = 0.5

	// MaxAssuranceTokenTTLSeconds caps the assurance-token lifetime (24h). An
	// assurance token carries no session and cannot be revoked, so an
	// unbounded TTL would be a permanent bearer credential.
	MaxAssuranceTokenTTLSeconds = 86400

	// MaxAssuranceChallengeTTLSeconds caps how long an attestation challenge
	// stays redeemable (1h). A challenge is a one-shot nonce; a long window
	// only widens the replay surface and the unreclaimed-row window.
	MaxAssuranceChallengeTTLSeconds = 3600

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

// DefaultExportMaxAuditEvents is the default cap on how many of the caller's
// own audit events a self-service data export includes (newest first). It
// bounds the export's audit scan when GATEWAY_EXPORT_MAX_AUDIT_EVENTS is unset;
// it mirrors service.DefaultExportMaxAuditEvents (the service-side safety
// clamp) so the boundary default matches the service's own fallback.
const DefaultExportMaxAuditEvents = 1000

// DefaultAuditRetentionDays is the default audit-log retention window in days
// (730 = 24 months). Audit events record security-relevant actions together
// with the caller's IP address and user-agent, so retaining them forever holds
// personal data with no storage limit; the background sweeper deletes events
// older than this window (GDPR Art 5(1)(e) storage limitation). 24 months is
// long enough for accountability and incident forensics yet bounded, so the
// trail cannot grow without end. GATEWAY_AUDIT_RETENTION_DAYS=0 (or negative)
// disables the sweep, preserving the pre-retention behaviour of keeping the
// trail indefinitely — the explicit opt-out for a legal hold or a longer
// statutory retention obligation.
const DefaultAuditRetentionDays = 730

// DefaultProjectIDFallback is the project id used when none is configured.
// It is the env-loader default for GATEWAY_DEFAULT_PROJECT_ID and the value
// app.New normalizes an empty DefaultProjectID to, so a directly-constructed
// Config (tests, embedding callers) never reaches the repo boundary with an
// empty project shard id. The single source of truth for this literal.
const DefaultProjectIDFallback = "default"

// DefaultProductFallback is the product slug attributed to a request that
// sends no X-Product header. It is the env-loader default for
// GATEWAY_DEFAULT_PRODUCT and names the household product that shipped the
// header first, so clients written before it existed keep resolving to the app
// they actually are. The single source of truth for this literal.
const DefaultProductFallback = "nesta"

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

	// DefaultProduct is the product slug attributed to a request that sends no
	// X-Product header — a client that predates the header. It names one of the
	// apps in the resolved project's `products` policy, so a legacy client is
	// gated as the deployment's primary app rather than as no product at all.
	// Set it to the slug an untagged client actually is. Driven by
	// GATEWAY_DEFAULT_PRODUCT (default "nesta", the first deployment to ship
	// the header); set it empty to leave untagged requests unrestricted.
	DefaultProduct string

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

	// DisableFirstAdminBootstrap closes the CreateFirstPlatformAdmin RPC — the
	// trust-on-first-use bootstrap of the first platform admin — entirely. When
	// true the RPC is rejected with FAILED_PRECONDITION regardless of whether any
	// admin exists yet, for operators who prefer the public bootstrap surface
	// shut. With it closed the first admin must be created another way: a direct
	// insert into platform_admins, or by toggling this off just long enough to
	// bootstrap and back on — no first-party seed CLI or migration ships for it.
	// It does NOT gate the other admin RPCs. The default false preserves the
	// zero-config bootstrap; note that when GATEWAY_ADMIN_API_SECRET is set the
	// bootstrap is already secret-gated even with this off. Driven by
	// GATEWAY_DISABLE_FIRST_ADMIN_BOOTSTRAP.
	DisableFirstAdminBootstrap bool

	// ProjectSecretsKey is the base64-encoded 32-byte AES-256 key that
	// encrypts per-project secrets at rest — currently the hosted-flow OAuth
	// provider secrets (client secrets, Apple private keys) stored in a
	// project's config_json. It is REQUIRED whenever the postgres control
	// plane is enabled (GATEWAY_REPO_DRIVER=postgres), because a non-default
	// project can only store provider credentials encrypted with this key;
	// Validate enforces that. Drivers without a control plane (memory, sqlite)
	// pin every request to the default project, which draws its OAuth
	// providers from the GATEWAY_OAUTH_* env vars, so the key is not required
	// there. Driven by GATEWAY_PROJECT_SECRETS_KEY.
	ProjectSecretsKey string

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

	// DefaultProjectAccessMode is the authentication access mode for the
	// env-configured default project, which has no config_json to carry an
	// `access` block: one of "open", "allowlist", "invite", or "closed" (see
	// service.AccessMode*). It DEFAULTS to "closed" (deny-all) so a deployment
	// that upgrades and sets nothing fails closed; a consumer product with open
	// self-signup (e.g. Nesta) sets GATEWAY_DEFAULT_PROJECT_ACCESS_MODE=open.
	// The project-resolution middleware stamps this onto the default-project
	// scope so the access guard sees a mode on every request. Driven by
	// GATEWAY_DEFAULT_PROJECT_ACCESS_MODE.
	DefaultProjectAccessMode string

	// DefaultProjectAllowedEmails is the comma-separated email allowlist applied
	// to the default project when DefaultProjectAccessMode is "allowlist"
	// (ignored for open/invite/closed). Driven by
	// GATEWAY_DEFAULT_PROJECT_ALLOWED_EMAILS.
	DefaultProjectAllowedEmails string

	// DefaultProjectAllowedDomains is the comma-separated email-domain allowlist
	// applied to the default project when DefaultProjectAccessMode is "allowlist"
	// (ignored for open/invite/closed). Driven by
	// GATEWAY_DEFAULT_PROJECT_ALLOWED_DOMAINS.
	DefaultProjectAllowedDomains string

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
	// MicrosoftAllowedTenants is the DEFAULT PROJECT's comma-separated allow-list
	// of accepted Azure AD directory (tenant) GUIDs for Microsoft sign-in
	// (hosted + native). When set, a Microsoft token whose `tid` is not a member
	// is rejected; it is the multi-tenant counterpart to the single-tenant
	// GATEWAY_MICROSOFT_TENANT_ID pin and closes the nOAuth account-takeover
	// vector for apps that trust several tenants. Non-default projects carry
	// their own allow-list in config_json (oauth.microsoft.allowed_tenants).
	MicrosoftAllowedTenants string
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

	// OIDCEnabled turns on the generic, config-driven OIDC provider so an
	// operator can register an arbitrary standards-compliant IdP (Okta,
	// Auth0, Keycloak, a self-hosted issuer) without a code release.
	OIDCEnabled bool
	// OIDCProviderKey is the registry key the generic OIDC provider is
	// registered under and reported as Identity.Provider (e.g. "okta").
	OIDCProviderKey string
	// OIDCIssuer is the generic OIDC provider's issuer URL; the discovery,
	// authorization, token, JWKS, and userinfo endpoints are resolved from
	// <issuer>/.well-known/openid-configuration unless OIDCDiscoveryURL is set.
	OIDCIssuer string
	// OIDCDiscoveryURL overrides the generic OIDC provider's discovery
	// document URL; empty = derived from OIDCIssuer.
	OIDCDiscoveryURL string
	// OIDCClientID is the generic OIDC provider's OAuth client ID.
	OIDCClientID string
	// OIDCClientSecret is the generic OIDC provider's OAuth client secret.
	OIDCClientSecret string
	// OIDCScopes overrides the space-separated OAuth scopes requested from
	// the generic OIDC provider; empty = "openid email profile" ("openid"
	// is always ensured).
	OIDCScopes string

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

	// OAuthHubSharing lets a non-default project with no OAuth provider of its
	// own borrow the default project's env-configured providers when routing
	// hosted OAuth through the central hub (the Firebase/Auth0 model: one
	// provider client + one registered redirect URI serve every project).
	// It is a deployment-level opt-in because it is only safe when all
	// projects belong to the same trust domain as the hub — the provider
	// consent screen shows the shared client's branding. A project's own
	// config_json.oauth providers always take precedence (ADR-0011). Driven
	// by GATEWAY_OAUTH_HUB_SHARING; defaults false (strict ADR-0010
	// isolation).
	OAuthHubSharing bool

	// OAuthPrompt is the OAuth `prompt` parameter forwarded to providers that
	// support it (Google, Microsoft) on the hosted authorization request.
	// Defaults to "select_account" so a signed-in user is always offered the
	// account chooser — without it the provider silently reuses its existing
	// SSO session, so after signing out of an app (whose local tokens were
	// cleared but whose provider session persists) the user cannot switch to a
	// different account. Set empty to disable (provider default). Driven by
	// GATEWAY_OAUTH_PROMPT.
	OAuthPrompt string

	// NativeOAuthEnabled is the kill-switch for NativeOAuthLogin (verifying
	// Google/Apple/Microsoft ID tokens from mobile SDKs). It defaults true when
	// at least one provider's DEFAULT-PROJECT native audiences are configured via
	// env, false otherwise; set it explicitly to true to enable the RPC for a
	// deployment that configures native audiences only per-project (config_json),
	// or to false to disable it even with env audiences present.
	NativeOAuthEnabled bool
	// NativeOAuthGoogleAudiences is the DEFAULT PROJECT's comma-separated
	// allow-list of accepted Google ID-token `aud` values for native login — the
	// web client id plus every per-platform (iOS/Android) OAuth client id.
	// Non-default projects configure their own via config_json
	// oauth.google.native_audiences and never inherit this. Empty disables Google
	// native login for the default project.
	NativeOAuthGoogleAudiences string
	// NativeOAuthAppleAudiences is the DEFAULT PROJECT's comma-separated
	// allow-list of accepted Apple ID-token `aud` values for native login — the
	// Services ID plus every native bundle id. Non-default projects configure
	// their own via config_json oauth.apple.native_audiences. Empty disables
	// Apple native login for the default project.
	NativeOAuthAppleAudiences string
	// NativeOAuthMicrosoftAudiences is the DEFAULT PROJECT's comma-separated
	// allow-list of accepted Microsoft ID-token `aud` values for native login.
	// Non-default projects configure their own via config_json
	// oauth.microsoft.native_audiences. Empty disables Microsoft native login for
	// the default project.
	NativeOAuthMicrosoftAudiences string
	// NativeOAuthProductProjects maps a native client's product selector to an
	// identity project id, as comma-separated product=projectID pairs (e.g.
	// "easyloops=proj_abc,tortoise=proj_def"). A product not listed falls back
	// to being treated as a project id directly. Token issuance is scoped to
	// the resolved project.
	NativeOAuthProductProjects string

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

	// Web-assurance (captcha) verification, the browser arm of the client-
	// assurance layer. When assurance is disabled the per-endpoint enforce
	// toggles are ignored; the toggles default true, so enabling assurance
	// gates every listed endpoint unless one is flipped off.

	// AssuranceWebProvider selects the pkg/assurance web implementation —
	// "turnstile" or "recaptcha_v3"; the matching secret must be set. Empty
	// disables web assurance (mobile-attestation-only deployment).
	AssuranceWebProvider string
	// AssuranceTurnstileSecret is the Cloudflare Turnstile secret key (provider "turnstile").
	AssuranceTurnstileSecret string
	// AssuranceTurnstileSiteKey is the Cloudflare Turnstile PUBLIC site key
	// (provider "turnstile"). Safe to expose: the hosted sign-up UI needs it
	// to render the widget, and the client passes the resulting token back.
	AssuranceTurnstileSiteKey string
	// AssuranceRecaptchaSecret is the reCAPTCHA v3 secret key (provider "recaptcha_v3").
	AssuranceRecaptchaSecret string
	// AssuranceRecaptchaScoreThreshold is the reCAPTCHA v3 score below which a
	// response is rejected; must be in [0,1].
	AssuranceRecaptchaScoreThreshold float64
	// AssuranceEnforcePasswordSignup requires an assurance token on the PasswordSignup endpoint.
	AssuranceEnforcePasswordSignup bool
	// AssuranceEnforcePasswordLogin requires an assurance token on the PasswordLogin endpoint.
	AssuranceEnforcePasswordLogin bool
	// AssuranceEnforcePasswordReset requires an assurance token on the RequestPasswordReset endpoint.
	AssuranceEnforcePasswordReset bool
	// AssuranceEnforceEmailLoginCode requires an assurance token on the RequestEmailLoginCode endpoint.
	AssuranceEnforceEmailLoginCode bool
	// AssuranceEnforceMagicLink requires an assurance token on the RequestMagicLink endpoint.
	AssuranceEnforceMagicLink bool
	// AssuranceEnforcePasskeySignup requires an assurance token on the BeginPasskeySignup endpoint.
	// Passkey registration is spammable without it — a script can forge valid
	// FIDO2 keypairs in software and set the UP/UV flags itself, so BeginPasskeySignup
	// is an unmetered account-creation + email-send surface just like PasswordSignup.
	AssuranceEnforcePasskeySignup bool

	// Client assurance (App Attest / Play Integrity / web captcha exchange).
	// AssuranceEnabled is the global on/off for the assurance token surface:
	// challenge issuance, evidence exchange, and refresh.
	AssuranceEnabled bool
	// AssuranceChallengeTTLSeconds bounds how long an issued attestation
	// challenge stays redeemable.
	AssuranceChallengeTTLSeconds int
	// AssuranceTokenTTLSeconds is the minted assurance token's lifetime.
	AssuranceTokenTTLSeconds int
	// AssuranceIOSTeamID is the DEFAULT project's Apple Developer team id for
	// App Attest (per-project apps configure theirs in config_json
	// `assurance.ios`). Empty disables iOS assurance for the default project.
	AssuranceIOSTeamID string
	// AssuranceIOSBundleID is the DEFAULT project's App Attest bundle id; set
	// together with AssuranceIOSTeamID (TeamID.BundleID forms the App ID).
	AssuranceIOSBundleID string
	// AssuranceIOSEnv selects the App Attest environment for the default
	// project: "production" (default) or "development".
	AssuranceIOSEnv string
	// AssuranceAndroidPackageName is the DEFAULT project's Play Integrity
	// Android package name (per-project apps configure theirs in config_json
	// `assurance.android`). Empty disables Android assurance for the default
	// project.
	AssuranceAndroidPackageName string
	// AssuranceAndroidCertDigests is the comma-separated allowlist of the
	// app's signing-certificate SHA-256 digests (unpadded base64url, as Play
	// reports them).
	AssuranceAndroidCertDigests string
	// AssuranceAndroidSAKeyJSON is the Google service-account key (inline
	// JSON) used to decode Play Integrity verdicts server-side.
	AssuranceAndroidSAKeyJSON string
	// AssuranceAllowProjectOnly permits booting with assurance enabled and NO
	// env-configured arm, for deployments where every app identity lives in
	// per-project config_json. It is an explicit acknowledgement that a
	// project without its own assurance block cannot authenticate at all.
	AssuranceAllowProjectOnly bool

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

	// SCIM 2.0 inbound provisioning (#260). When SCIMEnabled is false the
	// /scim/v2/* routes are not registered and return 404, leaving the
	// headless RPCs untouched. When true, SCIMBearerToken and SCIMProjectID
	// MUST both be set (enforced by Validate). The bearer token is the shared
	// secret an external IdP (Okta/Entra/Google) presents in the
	// Authorization: Bearer header on every SCIM request. The project id binds
	// that single credential to exactly one project: every SCIM operation
	// (create/list/get/replace/patch/delete) is constrained to that project's
	// users, so the deployment-wide token can never read or mutate another
	// project's user pool. A deployment that needs to provision multiple
	// projects runs one scoped credential per project.

	// SCIMEnabled gates the inbound SCIM 2.0 routes (default false).
	SCIMEnabled bool // GATEWAY_SCIM_ENABLED (default false)
	// SCIMBearerToken is the shared secret an external IdP presents in the
	// Authorization: Bearer header on every SCIM request (required when SCIMEnabled).
	SCIMBearerToken string // GATEWAY_SCIM_BEARER_TOKEN (required when SCIMEnabled)
	// SCIMProjectID is the single project whose users the SCIM endpoint
	// provisions; every SCIM operation is scoped to this project (required
	// when SCIMEnabled).
	SCIMProjectID string // GATEWAY_SCIM_PROJECT_ID (required when SCIMEnabled)

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

	// SAML 2.0 Identity Provider. Disabled by default; the server mounts no
	// SAML surface and holds a no-op issuer. When SAMLIDPEnabled is true the
	// entityID, SSO URL, and a signing key + certificate are required
	// (enforced by Validate). SLO URL is optional.

	// SAMLIDPEnabled turns on the SAML 2.0 IdP surface (default false).
	SAMLIDPEnabled bool
	// SAMLEntityID is the IdP entityID published in metadata (metadata URL).
	SAMLEntityID string
	// SAMLSSOURL is the HTTP-POST/Redirect single sign-on endpoint.
	SAMLSSOURL string
	// SAMLSLOURL is the optional single-logout endpoint.
	SAMLSLOURL string
	// SAMLSigningKey is the PEM-encoded RSA private key used to sign assertions.
	SAMLSigningKey string
	// SAMLSigningCert is the PEM-encoded X.509 certificate published in metadata.
	SAMLSigningCert string

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
	// RateLimitAssurancePerIP is the per-IP request cap per window on the
	// client-assurance endpoints. These are unauthenticated and each
	// IssueAssuranceToken / RefreshAssuranceToken call spends an outbound
	// provider request (Turnstile/reCAPTCHA siteverify, Google
	// decodeIntegrityToken), an RSA signature and an audit row, while
	// CreateAssuranceChallenge writes a DB row — so an uncapped path lets an
	// anonymous caller drive third-party quota, storage and outbound
	// amplification.
	RateLimitAssurancePerIP int
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

	// AccountDeletionGraceDays is the self-service deletion grace window (GDPR
	// Art 17): the number of days a PENDING_DELETION account is retained before
	// the sweeper hard-deletes it. A successful login (or explicit cancel)
	// during the window restores the account. Driven by
	// GATEWAY_ACCOUNT_DELETION_GRACE_DAYS (default 30); must be >= 1.
	AccountDeletionGraceDays int

	// ExportMaxAuditEvents caps how many of the caller's own audit events a
	// self-service data export (GDPR Art 15) includes, newest first. It bounds
	// the export's audit scan so a long-lived account can never return an
	// unbounded log. Driven by GATEWAY_EXPORT_MAX_AUDIT_EVENTS (default 1000);
	// a non-positive value falls back to the safe default.
	ExportMaxAuditEvents int

	// AuditRetentionDays is the audit-log retention window in days: on each tick
	// the background sweeper deletes audit events whose occurred-at instant is
	// older than now - AuditRetentionDays, so the service stops holding
	// audit/security logs (which record IP address and user-agent) indefinitely
	// (GDPR Art 5(1)(e) storage limitation). Driven by
	// GATEWAY_AUDIT_RETENTION_DAYS (default 730 = 24 months). A value <= 0
	// DISABLES retention — the sweep becomes a no-op and the trail is kept
	// forever — the explicit opt-out for a legal hold or a longer statutory
	// retention obligation.
	AuditRetentionDays int

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
	// WebhookSubscriptions is the raw JSON array declaring the outbound-webhook
	// endpoints seeded into the outbox at boot. Driven by
	// GATEWAY_WEBHOOK_SUBSCRIPTIONS; each element is a WebhookSubscription.
	// Parsed and validated by WebhookSubscriptionList (see
	// webhook_subscriptions.go). Empty ⇒ no subscriptions: with webhooks
	// enabled that is legal but inert (nothing is delivered). The secret in
	// each entry is sensitive and never logged.
	WebhookSubscriptions string
}

// Load reads configuration from environment variables with GATEWAY_
// prefix, falling back to sensible defaults for local development.
func Load() *Config {
	return &Config{
		GRPCPort:    envInt("GATEWAY_GRPC_PORT", 50051),
		ConnectPort: envInt("GATEWAY_CONNECT_PORT", 80),
		MetricsPort: envInt("GATEWAY_METRICS_PORT", 9090),

		RepoDriver: envStr("GATEWAY_REPO_DRIVER", "postgres"),

		DefaultTenantID:            envStr("GATEWAY_DEFAULT_TENANT_ID", "local"),
		DefaultProjectID:           envStr("GATEWAY_DEFAULT_PROJECT_ID", DefaultProjectIDFallback),
		DefaultProduct:             envStr("GATEWAY_DEFAULT_PRODUCT", DefaultProductFallback),
		AdminAPISecret:             envStr("GATEWAY_ADMIN_API_SECRET", ""),
		DisableFirstAdminBootstrap: envBool("GATEWAY_DISABLE_FIRST_ADMIN_BOOTSTRAP", false),
		ProjectSecretsKey:          envStr("GATEWAY_PROJECT_SECRETS_KEY", ""),
		DefaultProjectAuthDomains:  envStr("GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS", ""),
		// Default project access mode defaults to "closed" (deny-all): a
		// deployment that upgrades and configures nothing fails closed. Set
		// GATEWAY_DEFAULT_PROJECT_ACCESS_MODE=open to restore unrestricted signup.
		DefaultProjectAccessMode:     envStr("GATEWAY_DEFAULT_PROJECT_ACCESS_MODE", "closed"),
		DefaultProjectAllowedEmails:  envStr("GATEWAY_DEFAULT_PROJECT_ALLOWED_EMAILS", ""),
		DefaultProjectAllowedDomains: envStr("GATEWAY_DEFAULT_PROJECT_ALLOWED_DOMAINS", ""),
		RequireVerifiedAuthDomain:    envBool("GATEWAY_REQUIRE_VERIFIED_AUTH_DOMAIN", true),

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

		GoogleClientID:          envStr("GATEWAY_OAUTH_GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:      envStr("GATEWAY_OAUTH_GOOGLE_CLIENT_SECRET", ""),
		GoogleAuthorizationURL:  envStr("GATEWAY_OAUTH_GOOGLE_AUTHORIZATION_URL", ""),
		GoogleTokenURL:          envStr("GATEWAY_OAUTH_GOOGLE_TOKEN_URL", ""),
		GoogleJWKSURL:           envStr("GATEWAY_OAUTH_GOOGLE_JWKS_URL", ""),
		GoogleDiscoveryURL:      envStr("GATEWAY_OAUTH_GOOGLE_DISCOVERY_URL", ""),
		GoogleUserinfoURL:       envStr("GATEWAY_OAUTH_GOOGLE_USERINFO_URL", ""),
		GoogleIssuer:            envStr("GATEWAY_OAUTH_GOOGLE_ISSUER", ""),
		MicrosoftClientID:       envStr("GATEWAY_OAUTH_MICROSOFT_CLIENT_ID", ""),
		MicrosoftClientSecret:   envStr("GATEWAY_OAUTH_MICROSOFT_CLIENT_SECRET", ""),
		MicrosoftTenantID:       envStr("GATEWAY_MICROSOFT_TENANT_ID", ""),
		MicrosoftAllowedTenants: envStr("GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS", ""),
		GitHubClientID:          envStr("GATEWAY_OAUTH_GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:      envStr("GATEWAY_OAUTH_GITHUB_CLIENT_SECRET", ""),
		AppleClientID:           envStr("GATEWAY_OAUTH_APPLE_CLIENT_ID", ""),
		AppleTeamID:             envStr("GATEWAY_OAUTH_APPLE_TEAM_ID", ""),
		AppleKeyID:              envStr("GATEWAY_OAUTH_APPLE_KEY_ID", ""),
		ApplePrivateKey:         envStr("GATEWAY_OAUTH_APPLE_PRIVATE_KEY", ""),

		OIDCEnabled: envBool("GATEWAY_OAUTH_OIDC_ENABLED", false),
		// Normalize the provider key at the source so it matches the
		// lowercased/trimmed provider name the service uses for registry
		// lookups (see internal/service/auth_login.go).
		OIDCProviderKey:  strings.ToLower(strings.TrimSpace(envStr("GATEWAY_OAUTH_OIDC_PROVIDER_KEY", ""))),
		OIDCIssuer:       envStr("GATEWAY_OAUTH_OIDC_ISSUER", ""),
		OIDCDiscoveryURL: envStr("GATEWAY_OAUTH_OIDC_DISCOVERY_URL", ""),
		OIDCClientID:     envStr("GATEWAY_OAUTH_OIDC_CLIENT_ID", ""),
		OIDCClientSecret: envStr("GATEWAY_OAUTH_OIDC_CLIENT_SECRET", ""),
		OIDCScopes:       envStr("GATEWAY_OAUTH_OIDC_SCOPES", ""),

		OAuthAllowedReturnURLs: envStr("GATEWAY_OAUTH_ALLOWED_RETURN_URLS", ""),
		OAuthHubSharing:        envBool("GATEWAY_OAUTH_HUB_SHARING", false),
		OAuthPrompt:            envStrRaw("GATEWAY_OAUTH_PROMPT", "select_account"),

		NativeOAuthGoogleAudiences:    envStr("GATEWAY_NATIVE_OAUTH_GOOGLE_AUDIENCES", ""),
		NativeOAuthAppleAudiences:     envStr("GATEWAY_NATIVE_OAUTH_APPLE_AUDIENCES", ""),
		NativeOAuthMicrosoftAudiences: envStr("GATEWAY_NATIVE_OAUTH_MICROSOFT_AUDIENCES", ""),
		NativeOAuthProductProjects:    envStr("GATEWAY_NATIVE_OAUTH_PRODUCT_PROJECTS", ""),
		NativeOAuthEnabled: envBool("GATEWAY_NATIVE_OAUTH_ENABLED", nativeOAuthDefaultEnabled(
			envStr("GATEWAY_NATIVE_OAUTH_GOOGLE_AUDIENCES", ""),
			envStr("GATEWAY_NATIVE_OAUTH_APPLE_AUDIENCES", ""),
			envStr("GATEWAY_NATIVE_OAUTH_MICROSOFT_AUDIENCES", ""),
		)),

		IDVProvider:           envStr("GATEWAY_IDV_PROVIDER", ""),
		IDVAzureEndpoint:      envStr("GATEWAY_IDV_AZURE_ENDPOINT", ""),
		IDVAzureKey:           envStr("GATEWAY_IDV_AZURE_KEY", ""),
		IDVAzureSessionTTLSec: envInt("GATEWAY_IDV_AZURE_SESSION_TTL_SECONDS", 600),
		IDVRequired:           envBool("GATEWAY_IDV_REQUIRED", false),

		AssuranceWebProvider:             envStr("GATEWAY_ASSURANCE_WEB_PROVIDER", ""),
		AssuranceTurnstileSecret:         envStr("GATEWAY_ASSURANCE_TURNSTILE_SECRET", ""),
		AssuranceTurnstileSiteKey:        envStr("GATEWAY_ASSURANCE_TURNSTILE_SITE_KEY", ""),
		AssuranceRecaptchaSecret:         envStr("GATEWAY_ASSURANCE_RECAPTCHA_SECRET", ""),
		AssuranceRecaptchaScoreThreshold: envFloat("GATEWAY_ASSURANCE_RECAPTCHA_SCORE_THRESHOLD", DefaultAssuranceRecaptchaScoreThreshold),
		AssuranceEnforcePasswordSignup:   envBool("GATEWAY_ASSURANCE_ENFORCE_PASSWORD_SIGNUP", true),
		AssuranceEnforcePasswordLogin:    envBool("GATEWAY_ASSURANCE_ENFORCE_PASSWORD_LOGIN", true),
		AssuranceEnforcePasswordReset:    envBool("GATEWAY_ASSURANCE_ENFORCE_PASSWORD_RESET", true),
		AssuranceEnforceEmailLoginCode:   envBool("GATEWAY_ASSURANCE_ENFORCE_EMAIL_LOGIN_CODE", true),
		AssuranceEnforceMagicLink:        envBool("GATEWAY_ASSURANCE_ENFORCE_MAGIC_LINK", true),
		AssuranceEnforcePasskeySignup:    envBool("GATEWAY_ASSURANCE_ENFORCE_PASSKEY_SIGNUP", true),
		AssuranceEnabled:                 envBool("GATEWAY_ASSURANCE_ENABLED", false),
		AssuranceChallengeTTLSeconds:     envInt("GATEWAY_ASSURANCE_CHALLENGE_TTL_SECONDS", 300),
		AssuranceTokenTTLSeconds:         envInt("GATEWAY_ASSURANCE_TOKEN_TTL_SECONDS", 3600),
		AssuranceIOSTeamID:               envStr("GATEWAY_ASSURANCE_IOS_TEAM_ID", ""),
		AssuranceIOSBundleID:             envStr("GATEWAY_ASSURANCE_IOS_BUNDLE_ID", ""),
		AssuranceIOSEnv:                  envStr("GATEWAY_ASSURANCE_IOS_ENV", "production"),
		AssuranceAndroidPackageName:      envStr("GATEWAY_ASSURANCE_ANDROID_PACKAGE_NAME", ""),
		AssuranceAndroidCertDigests:      envStr("GATEWAY_ASSURANCE_ANDROID_CERT_SHA256_DIGESTS", ""),
		AssuranceAndroidSAKeyJSON:        envStr("GATEWAY_ASSURANCE_ANDROID_SA_KEY_JSON", ""),
		AssuranceAllowProjectOnly:        envBool("GATEWAY_ASSURANCE_ALLOW_PROJECT_ONLY", false),

		AgeGateEnabled:     envBool("GATEWAY_AGEGATE_ENABLED", false),
		AgeGateChildMaxAge: envInt("GATEWAY_AGEGATE_CHILD_MAX_AGE", DefaultAgeGateChildMaxAge),
		AgeGateAdultAge:    envInt("GATEWAY_AGEGATE_ADULT_AGE", DefaultAgeGateAdultAge),
		AgeGateRequireDOB:  envBool("GATEWAY_AGEGATE_REQUIRE_DOB", false),

		MinorDataMinimization: envBool("GATEWAY_MINOR_DATA_MINIMIZATION", false),

		SCIMEnabled:     envBool("GATEWAY_SCIM_ENABLED", false),
		SCIMBearerToken: envStr("GATEWAY_SCIM_BEARER_TOKEN", ""),
		SCIMProjectID:   envStr("GATEWAY_SCIM_PROJECT_ID", ""),

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

		SAMLIDPEnabled:  envBool("GATEWAY_SAML_IDP_ENABLED", false),
		SAMLEntityID:    envStr("GATEWAY_SAML_ENTITY_ID", ""),
		SAMLSSOURL:      envStr("GATEWAY_SAML_SSO_URL", ""),
		SAMLSLOURL:      envStr("GATEWAY_SAML_SLO_URL", ""),
		SAMLSigningKey:  envStr("GATEWAY_SAML_SIGNING_KEY", ""),
		SAMLSigningCert: envStr("GATEWAY_SAML_SIGNING_CERT", ""),

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
		RateLimitAssurancePerIP:    envInt("GATEWAY_RATE_LIMIT_ASSURANCE_PER_IP", 20),
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

		AccountDeletionGraceDays: envInt("GATEWAY_ACCOUNT_DELETION_GRACE_DAYS", 30),
		ExportMaxAuditEvents:     envInt("GATEWAY_EXPORT_MAX_AUDIT_EVENTS", DefaultExportMaxAuditEvents),
		AuditRetentionDays:       envInt("GATEWAY_AUDIT_RETENTION_DAYS", DefaultAuditRetentionDays),

		WebhooksEnabled:               envBool("GATEWAY_WEBHOOKS_ENABLED", false),
		WebhooksMaxAttempts:           envInt("GATEWAY_WEBHOOKS_MAX_ATTEMPTS", 6),
		WebhooksBackoffBaseSeconds:    envInt("GATEWAY_WEBHOOKS_BACKOFF_BASE_SECONDS", 2),
		WebhooksBackoffMaxSeconds:     envInt("GATEWAY_WEBHOOKS_BACKOFF_MAX_SECONDS", 300),
		WebhooksWorkerIntervalSeconds: envInt("GATEWAY_WEBHOOKS_WORKER_INTERVAL_SECONDS", 1),
		WebhooksBatchSize:             envInt("GATEWAY_WEBHOOKS_BATCH_SIZE", 50),
		WebhookSubscriptions:          envStr("GATEWAY_WEBHOOK_SUBSCRIPTIONS", ""),
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

// OIDCScopeList returns the configured generic-OIDC scopes split on
// whitespace, dropping blanks. An empty config yields nil, which lets the
// provider fall back to its default scope set ("openid email profile").
func (c *Config) OIDCScopeList() []string {
	fields := strings.Fields(c.OIDCScopes)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

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

// DefaultProjectAllowedEmailList returns the default project's access
// allowlist emails (comma-separated), trimmed with blanks dropped. Used only
// when DefaultProjectAccessMode is "allowlist". Canonicalization happens in the
// service layer (service.NewProjectAccessConfig), keeping this a pure split.
func (c *Config) DefaultProjectAllowedEmailList() []string {
	return splitNonEmptyCSV(c.DefaultProjectAllowedEmails)
}

// DefaultProjectAllowedDomainList returns the default project's access
// allowlist domains (comma-separated), trimmed with blanks dropped. Used only
// when DefaultProjectAccessMode is "allowlist".
func (c *Config) DefaultProjectAllowedDomainList() []string {
	return splitNonEmptyCSV(c.DefaultProjectAllowedDomains)
}

// splitNonEmptyCSV drops blank entries and yields nil (not an empty slice) for
// empty input, so an unset allowlist env var reads as "no entries".
func splitNonEmptyCSV(csv string) []string {
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		if v := strings.TrimSpace(raw); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// nativeOAuthDefaultEnabled reports the default for GATEWAY_NATIVE_OAUTH_ENABLED:
// on when at least one provider's DEFAULT-PROJECT native audiences are
// configured via env, off otherwise. Keeping the default audience-gated means a
// deployment that never configures env native audiences is unaffected; a
// deployment that configures native audiences only per-project (config_json)
// opts in explicitly with GATEWAY_NATIVE_OAUTH_ENABLED=true.
func nativeOAuthDefaultEnabled(audienceConfigs ...string) bool {
	for _, s := range audienceConfigs {
		if strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

// NativeOAuthGoogleAudienceList returns the default-project Google native
// audiences, trimmed, blanks dropped, in order. An empty config yields nil.
func (c *Config) NativeOAuthGoogleAudienceList() []string {
	return splitTrimCSV(c.NativeOAuthGoogleAudiences)
}

// NativeOAuthAppleAudienceList returns the default-project Apple native
// audiences, trimmed, blanks dropped, in order. An empty config yields nil.
func (c *Config) NativeOAuthAppleAudienceList() []string {
	return splitTrimCSV(c.NativeOAuthAppleAudiences)
}

// NativeOAuthMicrosoftAudienceList returns the default-project Microsoft native
// audiences, trimmed, blanks dropped, in order. An empty config yields nil.
func (c *Config) NativeOAuthMicrosoftAudienceList() []string {
	return splitTrimCSV(c.NativeOAuthMicrosoftAudiences)
}

// MicrosoftAllowedTenantList returns the default-project Microsoft tenant
// allow-list, trimmed, blanks dropped, in order. An empty config yields nil,
// which imposes no allow-list (the single-tenant GATEWAY_MICROSOFT_TENANT_ID
// pin, when set, still applies).
func (c *Config) MicrosoftAllowedTenantList() []string {
	return splitTrimCSV(c.MicrosoftAllowedTenants)
}

// microsoftTenantGUID matches an Azure AD directory (tenant) id — a canonical
// UUID. Azure ALWAYS stamps the token's `tid` as this GUID form, so it is the
// only value a tenant allow-list entry can ever match against.
var microsoftTenantGUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidMicrosoftTenant reports whether entry is a usable Azure AD tenant
// allow-list member: a directory (tenant) GUID, with no surrounding or embedded
// whitespace. It is the single source of the "what a tenant entry may look
// like" rule, shared by the env allow-list validation and the per-project
// config_json validation (internal/service). A verified-domain string is
// deliberately NOT valid — the token's `tid` is always a GUID, so a domain-form
// entry could never match and would silently reject every login; it is rejected
// at config time instead. A meta segment ("common"/"organizations"/"consumers")
// is likewise invalid — those denote multi-tenant and never appear as a `tid`.
func ValidMicrosoftTenant(entry string) bool {
	return microsoftTenantGUID.MatchString(entry)
}

// microsoftMetaTenants are the Azure AD "meta" tenant segments that denote a
// MULTI-tenant configuration (no single-directory pin). They are legal
// tenant_id pin values (interpreted as "no pin") but never legal allow-list
// entries. This mirrors the same set in pkg/oauth — Microsoft's fixed
// vocabulary, small and stable enough to state in both places rather than
// couple the packages.
var microsoftMetaTenants = map[string]bool{"common": true, "organizations": true, "consumers": true}

// ValidMicrosoftTenantPin reports whether entry is a valid single-tenant pin
// value for GATEWAY_MICROSOFT_TENANT_ID / oauth.microsoft.tenant_id: empty (no
// pin), a meta segment (common/organizations/consumers — multi-tenant, treated
// as no pin), or a directory (tenant) GUID. A verified-domain string (or any
// other non-GUID, non-meta value) is INVALID: the runtime guard requires
// tid == tenant_id and the token's `tid` is always a GUID, so a domain-form pin
// would reject every Microsoft login. Rejecting it at config time turns that
// silent 100% outage into a clear boot/write error.
func ValidMicrosoftTenantPin(entry string) bool {
	if entry == "" || microsoftMetaTenants[strings.ToLower(entry)] {
		return true
	}
	return microsoftTenantGUID.MatchString(entry)
}

// NativeOAuthAudienceList returns the default-project native audiences for a
// provider key ("google"/"apple"/"microsoft"), or nil for an unknown provider.
// These are the env seed the DEFAULT PROJECT falls back to; non-default projects
// carry their own audiences in config_json.
func (c *Config) NativeOAuthAudienceList(provider string) []string {
	switch provider {
	case "google":
		return c.NativeOAuthGoogleAudienceList()
	case "apple":
		return c.NativeOAuthAppleAudienceList()
	case "microsoft":
		return c.NativeOAuthMicrosoftAudienceList()
	}
	return nil
}

// IsDefaultProject reports whether id refers to the default project — the
// project that falls back to env-configured (default-project) settings (OAuth
// providers, native audiences). It delegates to the package-level
// IsDefaultProject rule using this Config's DefaultProjectID.
func (c *Config) IsDefaultProject(id string) bool {
	return IsDefaultProject(c.DefaultProjectID, id)
}

// IsDefaultProject reports whether id refers to the default project identified
// by defaultProjectID. An empty defaultProjectID (a Config built without a
// control plane) or an empty id means "default", so env settings apply to every
// request as they did before per-project config. It is the SINGLE SOURCE of the
// default/non-default rule, shared by the OAuth exchanger resolver (which holds
// only the id string) and native-audience resolution (via the Config method).
func IsDefaultProject(defaultProjectID, id string) bool {
	return defaultProjectID == "" || id == "" || id == defaultProjectID
}

// NativeOAuthProductProjectMap parses the product=projectID pairs into a map
// keyed by the lower-cased product selector. Malformed or blank entries are
// dropped; an empty config yields an empty (non-nil) map.
func (c *Config) NativeOAuthProductProjectMap() map[string]string {
	out := make(map[string]string)
	for _, raw := range strings.Split(c.NativeOAuthProductProjects, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		k, v, ok := strings.Cut(raw, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// splitTrimCSV splits a comma-separated string, trimming whitespace and
// dropping blank entries. An empty input yields nil.
func splitTrimCSV(s string) []string {
	var out []string
	for _, raw := range strings.Split(s, ",") {
		if v := strings.TrimSpace(raw); v != "" {
			out = append(out, v)
		}
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

// HasControlPlane reports whether the selected persistence driver carries
// a control plane — i.e. whether projects can hold their own config_json
// (and therefore their own assurance app identities). Only the postgres
// driver does; memory and sqlite pin every request to the default project.
func (c *Config) HasControlPlane() bool { return c.RepoDriver == "postgres" }

// AssuranceTokenTTL returns the assurance-token lifetime as a Duration.
func (c *Config) AssuranceTokenTTL() time.Duration {
	return time.Duration(c.AssuranceTokenTTLSeconds) * time.Second
}

// AssuranceAndroidCertDigestList splits the comma-separated digest list,
// dropping empties.
func (c *Config) AssuranceAndroidCertDigestList() []string {
	parts := strings.Split(c.AssuranceAndroidCertDigests, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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

// envStrRaw returns the env value when the key is SET — even to the empty
// string — and def only when the key is unset. Use it (instead of envStr) where
// an explicit empty value is a meaningful "disable", not "fall back to default".
func envStrRaw(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
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
// removedEnvVars maps an environment variable removed in a breaking
// release to the replacement an operator must set instead. Load ignores
// unknown variables by design, so a rename would otherwise take effect
// SILENTLY — for the v4.0.0 assurance rename that means an operator who
// pulls the new image keeps their old GATEWAY_CAPTCHA_* values, gets
// AssuranceEnabled=false, and loses anti-automation on six auth endpoints
// with no signal at all. Validate fails boot instead.
var removedEnvVars = map[string]string{
	"GATEWAY_CAPTCHA_ENABLED":                   "GATEWAY_ASSURANCE_ENABLED",
	"GATEWAY_CAPTCHA_PROVIDER":                  "GATEWAY_ASSURANCE_WEB_PROVIDER",
	"GATEWAY_CAPTCHA_TURNSTILE_SECRET":          "GATEWAY_ASSURANCE_TURNSTILE_SECRET",
	"GATEWAY_CAPTCHA_TURNSTILE_SITE_KEY":        "GATEWAY_ASSURANCE_TURNSTILE_SITE_KEY",
	"GATEWAY_CAPTCHA_RECAPTCHA_SECRET":          "GATEWAY_ASSURANCE_RECAPTCHA_SECRET",
	"GATEWAY_CAPTCHA_RECAPTCHA_SCORE_THRESHOLD": "GATEWAY_ASSURANCE_RECAPTCHA_SCORE_THRESHOLD",
	"GATEWAY_CAPTCHA_ENFORCE_PASSWORD_SIGNUP":   "GATEWAY_ASSURANCE_ENFORCE_PASSWORD_SIGNUP",
	"GATEWAY_CAPTCHA_ENFORCE_PASSWORD_LOGIN":    "GATEWAY_ASSURANCE_ENFORCE_PASSWORD_LOGIN",
	"GATEWAY_CAPTCHA_ENFORCE_PASSWORD_RESET":    "GATEWAY_ASSURANCE_ENFORCE_PASSWORD_RESET",
	"GATEWAY_CAPTCHA_ENFORCE_EMAIL_LOGIN_CODE":  "GATEWAY_ASSURANCE_ENFORCE_EMAIL_LOGIN_CODE",
	"GATEWAY_CAPTCHA_ENFORCE_MAGIC_LINK":        "GATEWAY_ASSURANCE_ENFORCE_MAGIC_LINK",
	"GATEWAY_CAPTCHA_ENFORCE_PASSKEY_SIGNUP":    "GATEWAY_ASSURANCE_ENFORCE_PASSKEY_SIGNUP",
}

// validateRemovedEnvVars fails boot when a removed variable is still set,
// naming its replacement. Sorted so the message is deterministic.
func validateRemovedEnvVars() error {
	var found []string
	for old, replacement := range removedEnvVars {
		if _, ok := os.LookupEnv(old); ok {
			found = append(found, fmt.Sprintf("%s (use %s)", old, replacement))
		}
	}
	if len(found) == 0 {
		return nil
	}
	sort.Strings(found)
	return fmt.Errorf(
		"config: %d environment variable(s) removed in v4.0.0 are still set: %s; see docs/UPGRADE.md",
		len(found), strings.Join(found, ", "),
	)
}

func (c *Config) Validate() error {
	if err := validateRemovedEnvVars(); err != nil {
		return err
	}

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

	if err := c.validateAssurance(); err != nil {
		return err
	}

	if err := c.validateWebhooks(); err != nil {
		return err
	}

	if err := c.validateAgeGate(); err != nil {
		return err
	}

	if err := c.validateSCIM(); err != nil {
		return err
	}

	if err := c.validateSAML(); err != nil {
		return err
	}

	if err := c.validateOIDC(); err != nil {
		return err
	}

	if err := c.validateNativeOAuth(); err != nil {
		return err
	}

	if err := c.validateMicrosoftTenants(); err != nil {
		return err
	}

	if err := c.validateProjectSecrets(); err != nil {
		return err
	}

	return nil
}

// projectSecretsKeyBytes is the required decoded length of
// GATEWAY_PROJECT_SECRETS_KEY (AES-256).
const projectSecretsKeyBytes = 32

// validateProjectSecrets enforces the per-project secrets-encryption invariant:
// GATEWAY_PROJECT_SECRETS_KEY is REQUIRED when the postgres control plane is
// enabled, because a non-default project can only store OAuth provider secrets
// encrypted with it. When set (on any driver) it must be base64 that decodes to
// exactly 32 bytes, failing fast rather than at first decrypt.
func (c *Config) validateProjectSecrets() error {
	if c.ProjectSecretsKey == "" {
		if c.RepoDriver == "postgres" {
			return errors.New("config: GATEWAY_PROJECT_SECRETS_KEY is required when GATEWAY_REPO_DRIVER=postgres " +
				"(it encrypts per-project OAuth provider secrets at rest); set a base64-encoded 32-byte key")
		}
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(c.ProjectSecretsKey)
	if err != nil {
		return fmt.Errorf("config: GATEWAY_PROJECT_SECRETS_KEY is not valid base64: %w", err)
	}
	if len(key) != projectSecretsKeyBytes {
		return fmt.Errorf("config: GATEWAY_PROJECT_SECRETS_KEY must decode to %d bytes, got %d",
			projectSecretsKeyBytes, len(key))
	}
	return nil
}

// validateNativeOAuth enforces the native mobile sign-in invariant: when
// enabled, either at least one provider's DEFAULT-PROJECT audiences are set via
// env, OR the deployment opted in explicitly (non-default projects carry their
// audiences in config_json, which config cannot see, so an explicit
// GATEWAY_NATIVE_OAUTH_ENABLED=true with no env audiences is valid). It also
// rejects a malformed product=projectID map.
func (c *Config) validateNativeOAuth() error {
	if !c.NativeOAuthEnabled {
		return nil
	}
	for _, raw := range strings.Split(c.NativeOAuthProductProjects, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		k, v, ok := strings.Cut(raw, "=")
		if !ok || strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("config: GATEWAY_NATIVE_OAUTH_PRODUCT_PROJECTS entry %q is malformed "+
				"(want product=projectID)", raw)
		}
	}
	return nil
}

// validateMicrosoftTenants rejects a malformed default-project Microsoft tenant
// pin at boot. The token's `tid` is always a directory GUID and the runtime
// guard compares against it, so a value that can never match must fail loudly
// here rather than silently reject every Microsoft login:
//
//   - GATEWAY_MICROSOFT_TENANT_ID must be empty, a meta segment
//     (common/organizations/consumers), or a directory GUID — a verified-domain
//     pin is rejected (it would break single-tenant sign-in entirely);
//   - every GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS entry must be a directory
//     GUID (meta and domain forms are both invalid in the allow-list).
func (c *Config) validateMicrosoftTenants() error {
	if !ValidMicrosoftTenantPin(c.MicrosoftTenantID) {
		return fmt.Errorf("config: GATEWAY_MICROSOFT_TENANT_ID %q must be an Azure AD directory (tenant) GUID, "+
			"a meta value (common/organizations/consumers), or empty (a verified-domain string can never match a token's tid)",
			c.MicrosoftTenantID)
	}
	for _, t := range c.MicrosoftAllowedTenantList() {
		if !ValidMicrosoftTenant(t) {
			return fmt.Errorf("config: GATEWAY_OAUTH_MICROSOFT_ALLOWED_TENANTS entry %q must be an "+
				"Azure AD directory (tenant) GUID (a verified-domain string can never match a token's tid)", t)
		}
	}
	return nil
}

// reservedOAuthProviderKeys are the built-in provider keys the generic
// OIDC provider may not reuse, so its registration cannot silently shadow
// a first-class provider.
var reservedOAuthProviderKeys = map[string]bool{
	"google": true, "microsoft": true, "github": true, "apple": true,
}

// validateOIDC enforces the generic config-driven OIDC provider invariants:
// when enabled, a provider key, client credentials, and either an issuer or
// an explicit discovery URL are all required, and the key must not collide
// with a built-in provider.
func (c *Config) validateOIDC() error {
	if !c.OIDCEnabled {
		return nil
	}
	key := strings.ToLower(strings.TrimSpace(c.OIDCProviderKey))
	if key == "" {
		return errors.New("config: GATEWAY_OAUTH_OIDC_ENABLED=true requires GATEWAY_OAUTH_OIDC_PROVIDER_KEY")
	}
	if reservedOAuthProviderKeys[key] {
		return fmt.Errorf("config: GATEWAY_OAUTH_OIDC_PROVIDER_KEY=%q is reserved for a built-in provider", key)
	}
	if strings.TrimSpace(c.OIDCIssuer) == "" && strings.TrimSpace(c.OIDCDiscoveryURL) == "" {
		return errors.New("config: GATEWAY_OAUTH_OIDC_ENABLED=true requires GATEWAY_OAUTH_OIDC_ISSUER or GATEWAY_OAUTH_OIDC_DISCOVERY_URL")
	}
	if strings.TrimSpace(c.OIDCClientID) == "" || strings.TrimSpace(c.OIDCClientSecret) == "" {
		return errors.New("config: GATEWAY_OAUTH_OIDC_ENABLED=true requires GATEWAY_OAUTH_OIDC_CLIENT_ID and GATEWAY_OAUTH_OIDC_CLIENT_SECRET")
	}
	return nil
}

// MinSCIMBearerTokenLength is the floor for GATEWAY_SCIM_BEARER_TOKEN. The
// token is the sole credential guarding account lifecycle operations across a
// whole project, so it must carry enough entropy to resist guessing; 32 chars
// is the minimum a generated secret should ever be.
const MinSCIMBearerTokenLength = 32

// validateSCIM enforces the SCIM invariant: a deployment that turns the
// inbound SCIM server on must supply a sufficiently long bearer token (the
// only credential gating account lifecycle operations) and a project id, since
// every SCIM operation is scoped to that single project's users. Failing closed
// at boot beats serving an unauthenticated, weakly-authenticated, or unscoped
// provisioning endpoint.
func (c *Config) validateSCIM() error {
	if !c.SCIMEnabled {
		return nil
	}
	if c.SCIMBearerToken == "" {
		return errors.New(
			"config: GATEWAY_SCIM_ENABLED=true requires GATEWAY_SCIM_BEARER_TOKEN to be set",
		)
	}
	if len(c.SCIMBearerToken) < MinSCIMBearerTokenLength {
		return fmt.Errorf(
			"config: GATEWAY_SCIM_BEARER_TOKEN must be at least %d characters (got %d)",
			MinSCIMBearerTokenLength, len(c.SCIMBearerToken),
		)
	}
	if c.SCIMProjectID == "" {
		return errors.New(
			"config: GATEWAY_SCIM_ENABLED=true requires GATEWAY_SCIM_PROJECT_ID to be set " +
				"(the single project whose users the SCIM endpoint provisions)",
		)
	}
	return nil
}

// validateWebhooks enforces the outbound-eventing invariants: the retry and
// backoff knobs must be positive, the cap must not be smaller than the base,
// and every declared subscription must be well-formed. The knob checks only
// run when eventing is enabled — a disabled deployment uses a no-op publisher
// and runs no worker, so its (unused) knobs are irrelevant — but a disabled
// deployment that nonetheless declares subscriptions is rejected, since those
// events would be silently dropped.
func (c *Config) validateWebhooks() error {
	if !c.WebhooksEnabled {
		// A subscription declared with the master switch off is almost
		// certainly a mistake: the events it asks for would be emitted to a
		// no-op publisher and silently dropped. Fail fast rather than boot
		// into a state that looks configured but delivers nothing.
		if strings.TrimSpace(c.WebhookSubscriptions) != "" {
			return errors.New(
				"config: GATEWAY_WEBHOOK_SUBSCRIPTIONS is set but GATEWAY_WEBHOOKS_ENABLED=false; " +
					"enable webhooks (GATEWAY_WEBHOOKS_ENABLED=true) or unset the subscriptions",
			)
		}
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
	// Fail fast on a malformed subscription (bad JSON, non-HTTPS URL, empty
	// secret, unknown event type) so a misconfigured deploy never serves a
	// request believing its webhooks are wired. Zero subscriptions is legal:
	// the composition root logs a warning that nothing will be delivered.
	if _, err := c.WebhookSubscriptionList(); err != nil {
		return err
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

// validateSAML enforces the SAML-IdP invariant: enabling the IdP requires
// an entityID, an SSO URL, and a signing key + certificate. A disabled
// deployment is unconstrained — the no-op issuer is wired and the fields
// are ignored. The cryptographic validity of the key/cert pair is checked
// when the issuer is constructed (samlidp.NewRSAIssuer); here we only fail
// closed on missing required values so the server never boots an "enabled
// but unusable" SAML surface.
func (c *Config) validateSAML() error {
	if !c.SAMLIDPEnabled {
		return nil
	}
	if c.SAMLEntityID == "" || c.SAMLSSOURL == "" {
		return errors.New(
			"config: GATEWAY_SAML_IDP_ENABLED=true requires GATEWAY_SAML_ENTITY_ID and GATEWAY_SAML_SSO_URL",
		)
	}
	if c.SAMLSigningKey == "" || c.SAMLSigningCert == "" {
		return errors.New(
			"config: GATEWAY_SAML_IDP_ENABLED=true requires GATEWAY_SAML_SIGNING_KEY and GATEWAY_SAML_SIGNING_CERT (PEM)",
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

// validateAssurance enforces the client-assurance invariants: an enabled
// deployment's configured surfaces must each be complete — a named web
// provider needs its secret (and, for reCAPTCHA v3, a threshold within
// [0,1]), a partially-specified default-project iOS or Android app
// identity fails rather than silently disabling the platform. A disabled
// deployment is unconstrained — the fields are ignored. A web provider is
// OPTIONAL when enabled: mobile-only deployments configure no captcha,
// and per-project deployments may configure everything in config_json.
func (c *Config) validateAssurance() error {
	if !c.AssuranceEnabled {
		return nil
	}

	if (c.AssuranceIOSTeamID == "") != (c.AssuranceIOSBundleID == "") {
		return errors.New("config: GATEWAY_ASSURANCE_IOS_TEAM_ID and GATEWAY_ASSURANCE_IOS_BUNDLE_ID must be set together")
	}
	switch c.AssuranceIOSEnv {
	case "", "production", "development":
	default:
		return fmt.Errorf("config: GATEWAY_ASSURANCE_IOS_ENV must be production or development, got %q", c.AssuranceIOSEnv)
	}
	if c.AssuranceAndroidPackageName != "" {
		if len(c.AssuranceAndroidCertDigestList()) == 0 {
			return errors.New("config: GATEWAY_ASSURANCE_ANDROID_PACKAGE_NAME requires GATEWAY_ASSURANCE_ANDROID_CERT_SHA256_DIGESTS")
		}
		if c.AssuranceAndroidSAKeyJSON == "" {
			return errors.New("config: GATEWAY_ASSURANCE_ANDROID_PACKAGE_NAME requires GATEWAY_ASSURANCE_ANDROID_SA_KEY_JSON")
		}
	}
	if c.AssuranceChallengeTTLSeconds <= 0 || c.AssuranceChallengeTTLSeconds > MaxAssuranceChallengeTTLSeconds {
		return fmt.Errorf(
			"config: GATEWAY_ASSURANCE_CHALLENGE_TTL_SECONDS must be in (0, %d], got %d",
			MaxAssuranceChallengeTTLSeconds, c.AssuranceChallengeTTLSeconds,
		)
	}
	// An assurance token is an unrevocable bearer credential for its whole
	// lifetime, so the TTL is capped as well as floored — the same reasoning
	// as RevocationModeTTLAccessTokenCap.
	if c.AssuranceTokenTTLSeconds <= 0 || c.AssuranceTokenTTLSeconds > MaxAssuranceTokenTTLSeconds {
		return fmt.Errorf(
			"config: GATEWAY_ASSURANCE_TOKEN_TTL_SECONDS must be in (0, %d], got %d",
			MaxAssuranceTokenTTLSeconds, c.AssuranceTokenTTLSeconds,
		)
	}

	// At least one arm must be usable. Enabling assurance turns the
	// per-endpoint enforce toggles on (all default true) while every path to
	// OBTAIN a token reports ErrAssuranceDisabled, so an enabled deployment
	// with nothing configured would boot cleanly and lock every user out of
	// signup, login, reset, email-code, magic-link and passkey-signup. Fail
	// boot instead — v3's validateCaptcha refused the analogous state.
	//
	// "Anywhere" matters: per-project app identities live in each project's
	// config_json, so a deployment WITH a control plane can legitimately
	// configure no env arm at all (the hub-style deployment the docs
	// describe). The env-arm requirement therefore applies only when there is
	// no control plane to carry per-project config, or when the operator
	// opts out explicitly.
	hasWeb := c.AssuranceWebProvider != ""
	hasIOS := c.AssuranceIOSTeamID != "" && c.AssuranceIOSBundleID != ""
	hasAndroid := c.AssuranceAndroidPackageName != ""
	if !hasWeb && !hasIOS && !hasAndroid &&
		!c.AssuranceAllowProjectOnly && !c.HasControlPlane() {
		return errors.New(
			"config: GATEWAY_ASSURANCE_ENABLED=true requires at least one configured arm — " +
				"a web provider (GATEWAY_ASSURANCE_WEB_PROVIDER), an iOS app " +
				"(GATEWAY_ASSURANCE_IOS_TEAM_ID + GATEWAY_ASSURANCE_IOS_BUNDLE_ID), " +
				"or an Android app (GATEWAY_ASSURANCE_ANDROID_PACKAGE_NAME) — " +
				"or GATEWAY_ASSURANCE_ALLOW_PROJECT_ONLY=true when every app identity " +
				"lives in per-project config_json; otherwise the enforce toggles deny " +
				"every auth endpoint with no way to obtain a token",
		)
	}

	switch c.AssuranceWebProvider {
	case "":
		// No web provider: mobile-attestation-only deployment (an iOS or
		// Android arm is present — the check above guarantees it).
		return nil
	case AssuranceWebProviderTurnstile:
		if c.AssuranceTurnstileSecret == "" {
			return fmt.Errorf("config: GATEWAY_ASSURANCE_ENABLED=true with provider %q requires GATEWAY_ASSURANCE_TURNSTILE_SECRET", AssuranceWebProviderTurnstile)
		}
		// The hosted sign-up UI needs the public site key to render the widget;
		// without it, enforcement would reject every browser sign-up.
		if c.AssuranceTurnstileSiteKey == "" {
			return fmt.Errorf("config: GATEWAY_ASSURANCE_ENABLED=true with provider %q requires GATEWAY_ASSURANCE_TURNSTILE_SITE_KEY", AssuranceWebProviderTurnstile)
		}
	case AssuranceWebProviderRecaptchaV3:
		if c.AssuranceRecaptchaSecret == "" {
			return fmt.Errorf("config: GATEWAY_ASSURANCE_ENABLED=true with provider %q requires GATEWAY_ASSURANCE_RECAPTCHA_SECRET", AssuranceWebProviderRecaptchaV3)
		}
		if c.AssuranceRecaptchaScoreThreshold < 0 || c.AssuranceRecaptchaScoreThreshold > 1 {
			return fmt.Errorf(
				"config: GATEWAY_ASSURANCE_RECAPTCHA_SCORE_THRESHOLD=%v must be in [0,1]",
				c.AssuranceRecaptchaScoreThreshold,
			)
		}
	default:
		return fmt.Errorf(
			"config: GATEWAY_ASSURANCE_ENABLED=true requires GATEWAY_ASSURANCE_WEB_PROVIDER to be one of: %q, %q; got %q",
			AssuranceWebProviderTurnstile, AssuranceWebProviderRecaptchaV3, c.AssuranceWebProvider,
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
