package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"

	"github.com/elloloop/identity/internal/config"
)

// ProjectConfig is the typed view of a project's config_json blob. It is the
// single decode target for everything an operator can configure per project
// in the control plane, so callers never reach into a raw map. New
// per-project knobs are added as fields here, not as scattered map lookups.
//
// Unknown keys are tolerated (forward compatibility): a config written by a
// newer server still decodes on an older one, ignoring fields it does not
// understand.
type ProjectConfig struct {
	// CORS holds the project's browser cross-origin policy.
	CORS ProjectCORSConfig `json:"cors"`

	// Branding holds the project's transactional-email branding. Every field
	// is optional; an unset field falls back to the global
	// GATEWAY_EMAIL_BRAND_* default (and, when that too is unset, to today's
	// byte-compatible output). This lets one server brand two products
	// (e.g. a kids app and a B2B app) distinctly.
	Branding ProjectBrandingConfig `json:"branding"`

	// Passkey holds the project's WebAuthn relying-party identity. When set,
	// it overrides the global GATEWAY_PASSKEY_* values for this project so a
	// passkey registered under one product's domain validates under that
	// product's RP-ID. Empty fields fall back to the global value.
	Passkey ProjectPasskeyConfig `json:"passkey"`

	// Login holds the project-wide login-method defaults applied to users
	// who have NO claimed tenant (the common case for a consumer pool). A
	// tenant's LoginPolicy, when one applies, fully overrides these.
	Login ProjectLoginConfig `json:"login"`

	// OAuth holds the project's own hosted-flow OAuth providers (the
	// Firebase-project model): each project enables and configures its own
	// Google/Microsoft/Apple/GitHub/OIDC providers, isolated from every other
	// project. A provider absent here is simply unavailable for the project,
	// EXCEPT the default project, which additionally inherits the env-configured
	// GATEWAY_OAUTH_* providers. Provider secrets are stored encrypted at rest
	// (see the *_enc fields).
	OAuth ProjectOAuthConfig `json:"oauth"`

	// Access holds the project's authentication access policy — the mode
	// (open/allowlist/invite/closed) that decides who may sign up, log in, and
	// accept invitations. It is DEFAULT-DENY: an empty or unset access block
	// (no mode) FAILS CLOSED and denies all authentication. A project must
	// explicitly set mode:open (or an allowlist/invite mode) to admit users.
	// See ProjectAccessConfig.
	Access ProjectAccessConfig `json:"access"`

	// Products holds the per-product guardrails applied to the products this
	// project's account pool signs into, keyed by the product slug a client
	// sends in the X-Product header. One account authenticates everywhere, but
	// each product's door checks the account's age band before a session is
	// issued for it. A product absent here is unrestricted.
	// See ProjectProductsConfig.
	Products ProjectProductsConfig `json:"products"`
	// Assurance holds the project's client-attestation identity — the mobile
	// app(s) whose hardware attestations this project accepts. A platform
	// absent here is unavailable for the project, EXCEPT the default project,
	// which inherits the env-configured GATEWAY_ASSURANCE_* app identity. The
	// Play service-account key is stored encrypted at rest (see the *_enc
	// field). Orthogonal to Access: assurance authenticates the CLIENT, the
	// access mode governs which USERS may authenticate.
	Assurance ProjectAssuranceConfig `json:"assurance"`

	// Anonymous holds the project's anonymous-sign-in policy: whether the
	// project hands out credential-less sessions at all, and how long an
	// idle one is retained. Default OFF. Orthogonal to Access — see
	// ProjectAnonymousConfig.
	Anonymous ProjectAnonymousConfig `json:"anonymous"`
}

// ProjectOAuthConfig is a project's per-provider hosted-flow OAuth
// configuration. Each field is a pointer so "absent" (nil) is distinct from
// "present but empty" — only a present provider is built for the project. The
// keys mirror the login `provider` argument callers pass ("google",
// "microsoft", "apple", "github", "oidc"). Like every other provider, a
// project's GitHub provider is configured here; the env GATEWAY_OAUTH_GITHUB_*
// credentials remain the DEFAULT project's provider only.
type ProjectOAuthConfig struct {
	Google    *ProjectOAuthGoogle    `json:"google,omitempty"`
	Microsoft *ProjectOAuthMicrosoft `json:"microsoft,omitempty"`
	Apple     *ProjectOAuthApple     `json:"apple,omitempty"`
	GitHub    *ProjectOAuthGitHub    `json:"github,omitempty"`
	OIDC      *ProjectOAuthOIDC      `json:"oidc,omitempty"`
}

// ProjectOAuthGoogle configures the project's Google provider. ClientID and
// ClientSecretEnc drive the hosted (code-exchange) flow; the URL fields are
// optional overrides that default to the live Google endpoints (used by tests /
// self-hosted proxies). NativeAudiences drives the native (mobile-SDK ID-token)
// flow independently — a project may configure hosted, native, or both.
type ProjectOAuthGoogle struct {
	ClientID         string `json:"client_id"`
	ClientSecretEnc  string `json:"client_secret_enc"`
	AuthorizationURL string `json:"authorization_url,omitempty"`
	TokenURL         string `json:"token_url,omitempty"`
	JWKSURL          string `json:"jwks_url,omitempty"`
	Issuer           string `json:"issuer,omitempty"`
	// NativeAudiences is the accepted native ID-token `aud` allow-list for this
	// project — the web client id plus every per-platform (iOS/Android) OAuth
	// client id a native SDK presents. Empty disables Google native login for
	// the project (unless it is the default project, which falls back to the
	// GATEWAY_NATIVE_OAUTH_GOOGLE_AUDIENCES env seed).
	NativeAudiences []string `json:"native_audiences,omitempty"`
}

// ProjectOAuthMicrosoft configures the project's Microsoft (Azure AD) provider.
// ClientID/ClientSecretEnc drive the hosted flow; NativeAudiences drives the
// native flow; TenantID/IssuerFormat pin the accepted issuer for both. A
// single-tenant project sets TenantID so only its tenant's tokens are accepted;
// leaving it empty keeps the multi-tenant default (issuer derived from the
// token's own `tid`).
type ProjectOAuthMicrosoft struct {
	ClientID        string `json:"client_id"`
	ClientSecretEnc string `json:"client_secret_enc"`
	TenantID        string `json:"tenant_id,omitempty"`
	IssuerFormat    string `json:"issuer_format,omitempty"`
	// AllowedTenants is a multi-tenant allow-list of Azure AD directory (tenant)
	// GUIDs: when non-empty, a Microsoft token whose `tid` is not a member is
	// rejected (hosted + native). It is the several-trusted-tenants counterpart
	// to the single-tenant TenantID pin, and closes the nOAuth account-takeover
	// vector for apps that accept more than one tenant — a token from any tenant
	// NOT on the list can no longer assert a victim's email. Entries must be
	// GUIDs (a domain-form string can never match a token's `tid`). Empty imposes
	// no allow-list.
	AllowedTenants []string `json:"allowed_tenants,omitempty"`
	// NativeAudiences is the accepted native ID-token `aud` allow-list for this
	// project. Empty disables Microsoft native login for the project (unless it
	// is the default project, which falls back to the
	// GATEWAY_NATIVE_OAUTH_MICROSOFT_AUDIENCES env seed).
	NativeAudiences []string `json:"native_audiences,omitempty"`
}

// ProjectOAuthApple configures the project's Apple provider. Apple has no
// client secret; the hosted flow signs a client assertion with a private key,
// stored encrypted at rest as PrivateKeyEnc. NativeAudiences drives the native
// flow independently — a project may configure hosted, native, or both.
type ProjectOAuthApple struct {
	ClientID      string `json:"client_id"`
	TeamID        string `json:"team_id"`
	KeyID         string `json:"key_id"`
	PrivateKeyEnc string `json:"private_key_enc"`
	// NativeAudiences is the accepted native ID-token `aud` allow-list for this
	// project — the Services ID plus every native bundle id. Empty disables
	// Apple native login for the project (unless it is the default project,
	// which falls back to the GATEWAY_NATIVE_OAUTH_APPLE_AUDIENCES env seed).
	NativeAudiences []string `json:"native_audiences,omitempty"`
}

// ProjectOAuthGitHub configures the project's GitHub provider. GitHub OAuth is
// NOT OIDC and has no ID token, so it is HOSTED-ONLY: ClientID and
// ClientSecretEnc drive the code→access_token exchange, after which the provider
// reads the user's profile and primary verified email from the GitHub REST API.
// The URL fields are optional overrides that default to the live GitHub
// endpoints (used by tests / self-hosted GitHub Enterprise proxies).
type ProjectOAuthGitHub struct {
	ClientID         string `json:"client_id"`
	ClientSecretEnc  string `json:"client_secret_enc"`
	AuthorizationURL string `json:"authorization_url,omitempty"`
	TokenURL         string `json:"token_url,omitempty"`
	UserURL          string `json:"user_url,omitempty"`
	UserMailURL      string `json:"user_mail_url,omitempty"`
}

// ProjectOAuthOIDC configures the project's generic OIDC provider, registered
// under the fixed key "oidc". Endpoints are discovered from Issuer's
// well-known document (or DiscoveryURL when set), mirroring the env OIDC
// provider — there are no per-endpoint overrides to keep dead knobs out.
type ProjectOAuthOIDC struct {
	ClientID        string `json:"client_id"`
	ClientSecretEnc string `json:"client_secret_enc"`
	Issuer          string `json:"issuer,omitempty"`
	DiscoveryURL    string `json:"discovery_url,omitempty"`
	// Scopes is a space-separated scope list; "openid" is always ensured by
	// the provider. Empty defaults to "openid email profile".
	Scopes string `json:"scopes,omitempty"`
}

// nativeAudiences returns the project's accepted native ID-token `aud`
// allow-list for a provider key ("google"/"apple"/"microsoft"), or nil when the
// project did not configure native audiences for it. The provider key is
// already lower-cased/trimmed by the caller.
func (c ProjectOAuthConfig) nativeAudiences(provider string) []string {
	switch provider {
	case "google":
		if c.Google != nil {
			return c.Google.NativeAudiences
		}
	case "apple":
		if c.Apple != nil {
			return c.Apple.NativeAudiences
		}
	case "microsoft":
		if c.Microsoft != nil {
			return c.Microsoft.NativeAudiences
		}
	}
	return nil
}

// ProjectBrandingConfig is the per-project transactional-email branding.
// All fields are optional. ProductName/LogoURL/PrimaryColor/SupportEmail are
// threaded into email template data; EmailFrom/EmailFromName build the SMTP
// From header; SupportEmail also drives the Reply-To header.
type ProjectBrandingConfig struct {
	// ProductName is the human-facing product name shown in email bodies
	// (e.g. "Glassa Kids"). Empty falls back to the global default.
	ProductName string `json:"product_name"`

	// EmailFrom is the bare From address for this project's mail
	// (e.g. "no-reply@kids.example.com"). Empty falls back to the global
	// default (GATEWAY_EMAIL_BRAND_FROM, else GATEWAY_SMTP_FROM).
	EmailFrom string `json:"email_from"`

	// EmailFromName is the display name shown in the From header
	// (e.g. "Glassa Kids"). Empty falls back to the global default.
	EmailFromName string `json:"email_from_name"`

	// LogoURL is an absolute https URL to the product logo, shown in HTML
	// email. Empty omits the logo (today's behaviour).
	LogoURL string `json:"logo_url"`

	// PrimaryColor is a CSS colour (e.g. "#1a73e8") used to tint branded
	// HTML email. Empty falls back to the global default.
	PrimaryColor string `json:"primary_color"`

	// SupportEmail is the address users can reply to / contact. When set it
	// drives the Reply-To header and is shown in email footers. Empty omits
	// Reply-To.
	SupportEmail string `json:"support_email"`
}

// ProjectPasskeyConfig is the per-project WebAuthn relying-party identity.
type ProjectPasskeyConfig struct {
	// RPID is the WebAuthn relying-party id (an effective domain, no scheme
	// or port, e.g. "kids.example.com"). Empty falls back to the global
	// GATEWAY_PASSKEY_RP_ID.
	RPID string `json:"rp_id"`

	// RPName is the human-facing relying-party name. Empty falls back to the
	// global GATEWAY_PASSKEY_RP_NAME.
	RPName string `json:"rp_name"`

	// Origin is the expected WebAuthn origin (scheme+host(+port), e.g.
	// "https://kids.example.com"). Empty falls back to the global
	// GATEWAY_PASSKEY_ORIGIN.
	Origin string `json:"origin"`
}

// Validate checks the optional branding/passkey blocks are well-formed when
// set. It is invariant-only: every field stays optional (an unset field is
// valid and means "fall back to the global default"); a *set* field that is
// malformed is a configuration error the write path must reject rather than
// persist a value that would later produce a broken email or a passkey that
// silently never validates.
func (c ProjectConfig) Validate() error {
	if err := c.Branding.validate(); err != nil {
		return err
	}
	if err := c.Passkey.validate(); err != nil {
		return err
	}
	if err := c.OAuth.validate(); err != nil {
		return err
	}
	if err := c.Access.validate(); err != nil {
		return err
	}
	if err := c.Products.validate(); err != nil {
		return err
	}
	if err := c.Assurance.validate(); err != nil {
		return err
	}
	if err := c.Anonymous.validate(); err != nil {
		return err
	}
	return nil
}

// validate rejects a present-but-incomplete provider block. A provider block
// may enable the hosted flow (code exchange), the native flow (mobile-SDK
// ID-token verification via native_audiences), or both — independently. The
// rules per block are:
//
//   - hosted credentials, when ANY are present, must be COMPLETE (a half-filled
//     hosted block fails the write rather than silently producing a provider
//     that can never complete a login);
//   - a block with no hosted credentials is valid only if it enables the native
//     flow (native_audiences non-empty); a wholly empty block is a config error.
//
// Absent providers (nil) are valid — they mean "not enabled for this project".
// URL fields are validated when set. Secrets are opaque ciphertext here
// (validated at decrypt time), so only their presence is checked.
func (c ProjectOAuthConfig) validate() error {
	if c.Google != nil {
		if err := c.Google.validate(); err != nil {
			return err
		}
	}
	if c.Microsoft != nil {
		if err := c.Microsoft.validate(); err != nil {
			return err
		}
	}
	if c.Apple != nil {
		if err := c.Apple.validate(); err != nil {
			return err
		}
	}
	if c.GitHub != nil {
		if err := c.GitHub.validate(); err != nil {
			return err
		}
	}
	if c.OIDC != nil {
		if err := c.OIDC.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (g *ProjectOAuthGoogle) validate() error {
	hosted := g.ClientID != "" || g.ClientSecretEnc != ""
	if hosted && (g.ClientID == "" || g.ClientSecretEnc == "") {
		return errors.New("oauth.google requires client_id and client_secret_enc")
	}
	if !hosted && len(g.NativeAudiences) == 0 {
		return errors.New("oauth.google requires client_id and client_secret_enc, or native_audiences")
	}
	for field, raw := range map[string]string{
		"oauth.google.authorization_url": g.AuthorizationURL,
		"oauth.google.token_url":         g.TokenURL,
		"oauth.google.jwks_url":          g.JWKSURL,
	} {
		if raw != "" {
			if err := validateHTTPSURL(raw, field); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *ProjectOAuthMicrosoft) validate() error {
	hosted := m.ClientID != "" || m.ClientSecretEnc != ""
	if hosted && (m.ClientID == "" || m.ClientSecretEnc == "") {
		return errors.New("oauth.microsoft requires client_id and client_secret_enc")
	}
	if !hosted && len(m.NativeAudiences) == 0 {
		return errors.New("oauth.microsoft requires client_id and client_secret_enc, or native_audiences")
	}
	// The issuer is built with fmt.Sprintf(IssuerFormat, tid), so the format
	// must carry exactly one %s verb. A format with zero or extra verbs would
	// render a malformed issuer (…%!(EXTRA…) / %!s(MISSING)) that no real
	// token could ever match, silently failing every login — reject it at
	// author time. Both the write path and resolution enforce this.
	if m.IssuerFormat != "" {
		if err := validateSingleStringVerb(m.IssuerFormat, "oauth.microsoft.issuer_format"); err != nil {
			return err
		}
	}
	// tenant_id pins verification (tid == tenant_id) for a concrete GUID, so a
	// domain-form pin would reject every login. Accept empty (no pin), a meta
	// value (multi-tenant), or a GUID; reject anything else at author time.
	if !config.ValidMicrosoftTenantPin(m.TenantID) {
		return fmt.Errorf("oauth.microsoft.tenant_id %q must be an Azure AD directory (tenant) GUID, "+
			"a meta value (common/organizations/consumers), or empty (a verified-domain string can never match a token's tid)",
			m.TenantID)
	}
	for _, t := range m.AllowedTenants {
		if !config.ValidMicrosoftTenant(t) {
			return fmt.Errorf("oauth.microsoft.allowed_tenants entry %q must be an Azure AD directory (tenant) GUID "+
				"(a verified-domain string can never match a token's tid)", t)
		}
	}
	return nil
}

func (a *ProjectOAuthApple) validate() error {
	hosted := a.ClientID != "" || a.TeamID != "" || a.KeyID != "" || a.PrivateKeyEnc != ""
	if hosted && (a.ClientID == "" || a.TeamID == "" || a.KeyID == "" || a.PrivateKeyEnc == "") {
		return errors.New("oauth.apple requires client_id, team_id, key_id, and private_key_enc")
	}
	if !hosted && len(a.NativeAudiences) == 0 {
		return errors.New("oauth.apple requires client_id, team_id, key_id, and private_key_enc, or native_audiences")
	}
	return nil
}

func (g *ProjectOAuthGitHub) validate() error {
	// GitHub is hosted-only (no native ID-token flow), so both credentials are
	// unconditionally required — there is no native_audiences alternative that
	// would make a credential-less block valid.
	if g.ClientID == "" || g.ClientSecretEnc == "" {
		return errors.New("oauth.github requires client_id and client_secret_enc")
	}
	for field, raw := range map[string]string{
		"oauth.github.authorization_url": g.AuthorizationURL,
		"oauth.github.token_url":         g.TokenURL,
		"oauth.github.user_url":          g.UserURL,
		"oauth.github.user_mail_url":     g.UserMailURL,
	} {
		if raw != "" {
			if err := validateHTTPSURL(raw, field); err != nil {
				return err
			}
		}
	}
	return nil
}

func (o *ProjectOAuthOIDC) validate() error {
	if o.ClientID == "" || o.ClientSecretEnc == "" {
		return errors.New("oauth.oidc requires client_id and client_secret_enc")
	}
	if o.Issuer == "" && o.DiscoveryURL == "" {
		return errors.New("oauth.oidc requires issuer or discovery_url")
	}
	if o.Issuer != "" {
		if err := validateHTTPSURL(o.Issuer, "oauth.oidc.issuer"); err != nil {
			return err
		}
	}
	if o.DiscoveryURL != "" {
		if err := validateHTTPSURL(o.DiscoveryURL, "oauth.oidc.discovery_url"); err != nil {
			return err
		}
	}
	return nil
}

func (b ProjectBrandingConfig) validate() error {
	if b.EmailFrom != "" {
		if _, err := mail.ParseAddress(b.EmailFrom); err != nil {
			return fmt.Errorf("branding.email_from %q is not a valid address: %w", b.EmailFrom, err)
		}
	}
	if b.SupportEmail != "" {
		if _, err := mail.ParseAddress(b.SupportEmail); err != nil {
			return fmt.Errorf("branding.support_email %q is not a valid address: %w", b.SupportEmail, err)
		}
	}
	if b.LogoURL != "" {
		if err := validateHTTPSURL(b.LogoURL, "branding.logo_url"); err != nil {
			return err
		}
	}
	return nil
}

func (p ProjectPasskeyConfig) validate() error {
	if p.RPID != "" {
		// An RP-ID is a bare effective domain: no scheme, no port, no path.
		if strings.ContainsAny(p.RPID, "/:") {
			return fmt.Errorf("passkey.rp_id %q must be a bare domain (no scheme, port, or path)", p.RPID)
		}
	}
	if p.Origin != "" {
		if err := validateHTTPURL(p.Origin, "passkey.origin"); err != nil {
			return err
		}
	}
	return nil
}

// validateSingleStringVerb rejects a fmt format string that does not contain
// exactly one %s verb (and no other verb). A literal percent (%%) is allowed.
func validateSingleStringVerb(format, field string) error {
	stripped := strings.ReplaceAll(format, "%%", "")
	if strings.Count(stripped, "%s") != 1 || strings.Count(stripped, "%") != 1 {
		return fmt.Errorf("%s %q must contain exactly one %%s verb", field, format)
	}
	return nil
}

func validateHTTPSURL(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q is not a valid URL: %w", field, raw, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s %q must be an absolute https:// URL", field, raw)
	}
	return nil
}

func validateHTTPURL(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q is not a valid URL: %w", field, raw, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%s %q must be an absolute http(s):// origin", field, raw)
	}
	return nil
}

// ProjectLoginConfig is the project-wide login-method default, layered UNDER
// any tenant LoginPolicy (tenant overrides project overrides global). It lets
// an operator constrain authentication for an ENTIRE project — e.g. a kids
// pool that disables passkeys/OAuth/SSO — for users whose email domain maps
// to no claimed tenant, who would otherwise get no restriction at all.
//
// The zero value is "no project-wide restriction", so an existing project
// with empty config_json behaves exactly as before.
type ProjectLoginConfig struct {
	// AllowedMethods is a comma-separated allow-list of login method tokens
	// (see service LoginMethod*). Empty means no project-wide restriction.
	AllowedMethods string `json:"allowed_methods"`
	// Require2FA forces a second factor after the primary method for every
	// user in the project who is not governed by a tenant policy.
	Require2FA bool `json:"require_2fa"`
}

// Access modes an operator selects per project via config_json `access.mode`
// (and, for the env-configured default project, via
// GATEWAY_DEFAULT_PROJECT_ACCESS_MODE). The mode is REQUIRED to authenticate:
// an unset/empty/unrecognized mode denies (see enforceProjectAccess). This is
// the deliberate default-DENY posture — the inverse of an opt-in allowlist —
// so a project (or a whole deployment) that has not been explicitly opened
// cannot authenticate anyone.
const (
	// AccessModeOpen permits everyone — signup and login are unrestricted.
	// This reproduces the pre-access-control behavior; a consumer product
	// (e.g. Nesta) that wants open self-signup sets this explicitly.
	AccessModeOpen = "open"
	// AccessModeAllowlist permits only a user whose canonical email is in
	// AllowedEmails OR whose domain is in AllowedDomains — for BOTH signup and
	// login (and invitation acceptance). Requires at least one entry.
	AccessModeAllowlist = "allowlist"
	// AccessModeInvite denies self-signup but permits login for an already
	// provisioned user and permits admin-issued invitation acceptance — genuine
	// per-project invite-only, independent of the deployment-global signup
	// toggles. AllowedEmails/AllowedDomains are unused (rejected if supplied).
	AccessModeInvite = "invite"
	// AccessModeClosed denies everyone — signup, login, and invitation
	// acceptance all fail. The explicit "this project is sealed" mode.
	AccessModeClosed = "closed"
)

// ProjectAccessConfig is the per-project authentication access policy, parsed
// from config_json `access` (or, for the default project, assembled from env).
// Its Mode selects one of the four behaviors above; AllowedEmails/AllowedDomains
// apply only to AccessModeAllowlist.
//
// Fail direction — DEFAULT-DENY. Unlike the login-method policy
// (login_policy_enforce.go), which fails OPEN so a misconfiguration never locks
// a tenant out, access control exists to gate membership, so an unset/empty/
// unrecognized mode DENIES (enforceProjectAccess), and a malformed access block
// is rejected by ParseProjectConfig — which makes the project resolver refuse
// the project entirely rather than silently resolve it open.
type ProjectAccessConfig struct {
	// Mode is one of AccessMode{Open,Allowlist,Invite,Closed}. Empty/unset or
	// unrecognized is treated as deny-all at enforcement time.
	Mode string `json:"mode"`

	// AllowedEmails is the explicit per-address allowlist for AccessModeAllowlist.
	// Entries are validated as well-formed emails and canonicalized
	// (canonicalizeEmail) at parse time, so a listed alice.smith+tag@gmail.com
	// matches a login as alicesmith@gmail.com.
	AllowedEmails []string `json:"allowed_emails"`

	// AllowedDomains is the allowlist of email domains (the part after '@') for
	// AccessModeAllowlist. Entries are canonicalized (canonicalizeDomain —
	// lower-cased, IDN-punycoded, googlemail.com folded to gmail.com) at parse
	// time. A user whose email domain is listed is permitted even when their
	// exact address is absent from AllowedEmails.
	AllowedDomains []string `json:"allowed_domains"`
}

// NewProjectAccessConfig builds and validates an access policy from separate
// mode + allowlist parts (as opposed to a config_json blob), applying the SAME
// validation and canonicalization as the config_json path so both are gated by
// identical rules. A malformed spec is returned as an error — never silently
// downgraded to open.
func NewProjectAccessConfig(mode string, allowedEmails, allowedDomains []string) (ProjectAccessConfig, error) {
	a := ProjectAccessConfig{Mode: mode, AllowedEmails: allowedEmails, AllowedDomains: allowedDomains}
	if err := a.validate(); err != nil {
		return ProjectAccessConfig{}, err
	}
	return a.canonicalized(), nil
}

// mode normalizes the raw mode (trim + lower-case) so comparisons against the
// AccessMode* constants hold regardless of config casing or whitespace.
func (a ProjectAccessConfig) mode() string {
	return strings.TrimSpace(strings.ToLower(a.Mode))
}

// validate rejects a malformed access block so it fails the whole config parse
// (and thus project resolution) rather than degrading to an open project. The
// rules encode the mode matrix: allowlist REQUIRES at least one entry (use
// "closed" for deny-all); every other mode REJECTS allowlist entries (they would
// be inert — fail loud); an unrecognized non-empty mode is rejected. An empty
// mode with no entries is a valid config that denies at enforcement time (the
// default-DENY posture for a project with no access block).
func (a ProjectAccessConfig) validate() error {
	hasEntries := len(a.AllowedEmails) > 0 || len(a.AllowedDomains) > 0
	switch a.mode() {
	case "", AccessModeOpen, AccessModeClosed, AccessModeInvite:
		if hasEntries {
			return fmt.Errorf("access: allowed_emails/allowed_domains are only valid with mode %q (mode is %q)", AccessModeAllowlist, a.Mode)
		}
	case AccessModeAllowlist:
		if !hasEntries {
			return fmt.Errorf("access: mode %q requires at least one allowed_emails or allowed_domains entry (use mode %q to deny all)", AccessModeAllowlist, AccessModeClosed)
		}
		if err := a.validateEntries(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("access.mode %q must be one of %q, %q, %q, %q", a.Mode,
			AccessModeOpen, AccessModeAllowlist, AccessModeInvite, AccessModeClosed)
	}
	return nil
}

// validateEntries rejects malformed allowlist entries up front, routing emails
// through the same validateEmailFormat gate as every email-bearing RPC so the
// allowlist can never admit an address the system would otherwise reject.
func (a ProjectAccessConfig) validateEntries() error {
	for _, raw := range a.AllowedEmails {
		e := strings.TrimSpace(raw)
		if e == "" {
			return errors.New("access.allowed_emails entries must not be empty")
		}
		if err := validateEmailFormat(strings.ToLower(e)); err != nil {
			return fmt.Errorf("access.allowed_emails entry %q is not a valid email: %w", raw, err)
		}
	}
	for _, raw := range a.AllowedDomains {
		d := strings.TrimSpace(raw)
		if d == "" {
			return errors.New("access.allowed_domains entries must not be empty")
		}
		if strings.Contains(d, "@") {
			return fmt.Errorf("access.allowed_domains entry %q must be a bare domain, not an email address", raw)
		}
		if !strings.Contains(d, ".") {
			return fmt.Errorf("access.allowed_domains entry %q must be a domain containing a dot", raw)
		}
	}
	return nil
}

// canonicalized returns a copy whose mode is normalized and whose emails and
// domains are canonicalized to the same form a login email is compared against,
// so allowlist matching is like-against-like. Applied once at parse time
// (ParseProjectConfig) so every downstream copy carries canonical values.
func (a ProjectAccessConfig) canonicalized() ProjectAccessConfig {
	out := ProjectAccessConfig{Mode: a.mode()}
	if len(a.AllowedEmails) > 0 {
		out.AllowedEmails = make([]string, 0, len(a.AllowedEmails))
		for _, e := range a.AllowedEmails {
			out.AllowedEmails = append(out.AllowedEmails, canonicalizeEmail(e))
		}
	}
	if len(a.AllowedDomains) > 0 {
		out.AllowedDomains = make([]string, 0, len(a.AllowedDomains))
		for _, d := range a.AllowedDomains {
			out.AllowedDomains = append(out.AllowedDomains, canonicalizeDomain(d))
		}
	}
	return out
}

// permits reports whether email is on the allowlist. Its parameter is a
// canonicalEmail, so the "caller MUST pass an already-canonicalized address"
// precondition (entries are canonicalized at parse time, so a raw address would
// spuriously miss) is now enforced by the compiler rather than a comment. Only
// consulted for AccessModeAllowlist.
func (a ProjectAccessConfig) permits(email canonicalEmail) bool {
	canonical := string(email)
	for _, e := range a.AllowedEmails {
		if e == canonical {
			return true
		}
	}
	domain := emailDomain(canonical)
	if domain == "" {
		return false
	}
	for _, d := range a.AllowedDomains {
		if d == domain {
			return true
		}
	}
	return false
}

// Minimum age bands an operator may set on a product via config_json
// `products.<slug>.minimum_age_band`. They are the lower-cased spellings of the
// agegate.Band* classifications a user's date of birth derives into, so config
// reads as prose ("hold is teen and up") while the comparison stays a single
// ordering.
const (
	// MinimumAgeBandChild admits every account with a known band — the CHILD
	// band is already the lowest. It exists so an operator can state "no
	// restriction" explicitly rather than by omission.
	MinimumAgeBandChild = "child"
	// MinimumAgeBandTeen refuses CHILD accounts; TEEN and ADULT pass.
	MinimumAgeBandTeen = "teen"
	// MinimumAgeBandAdult refuses CHILD and TEEN accounts; only ADULT passes.
	MinimumAgeBandAdult = "adult"
)

// ProjectProductConfig is one product's guardrail policy.
type ProjectProductConfig struct {
	// MinimumAgeBand is the lowest age band this product issues a session for,
	// one of MinimumAgeBand{Child,Teen,Adult}. Empty means the product imposes
	// no age restriction.
	MinimumAgeBand string `json:"minimum_age_band"`
}

// ProjectProductsConfig maps a product slug (the value of the X-Product header)
// to that product's guardrail policy. It is the enforcement half of "one
// account, many products": the account pool is shared, so a product's audience
// rating has to be enforced at the door rather than assumed from store listing
// copy.
//
// Fail direction — FAIL OPEN, the opposite of ProjectAccessConfig. An absent
// products block, an absent slug, and an absent minimum_age_band all mean "no
// age restriction", so adding the feature changes no existing deployment's
// behavior and a product is gated only once an operator says so. What DOES fail
// loudly is a malformed policy: an unrecognized band string is rejected by
// ParseProjectConfig, which makes the project resolver refuse the project rather
// than serve a typo as "unrestricted".
type ProjectProductsConfig map[string]ProjectProductConfig

// minimumAgeBandRank orders the bands for the "is this account old enough"
// comparison. Rank 0 is "no constraint / unknown" and always passes, which is
// what makes both an unconfigured product and an account with no derived band
// (agegate.BandUnknown) fall through the gate.
var minimumAgeBandRank = map[string]int{
	MinimumAgeBandChild: 1,
	MinimumAgeBandTeen:  2,
	MinimumAgeBandAdult: 3,
}

// validate rejects a malformed products block so the whole config parse fails
// (and with it project resolution) rather than silently ignoring a policy the
// operator believes is in force. A blank slug is rejected because it can never
// match a header; an unrecognized band is rejected because "chid" would
// otherwise read as "unrestricted" — exactly the guardrail the operator asked
// for, silently absent.
func (p ProjectProductsConfig) validate() error {
	for slug, product := range p {
		if strings.TrimSpace(slug) == "" {
			return errors.New("products: product slugs must not be empty")
		}
		band := normalizeProductSlug(product.MinimumAgeBand)
		if band == "" {
			continue
		}
		if _, ok := minimumAgeBandRank[band]; !ok {
			return fmt.Errorf("products.%s.minimum_age_band %q must be one of %q, %q, %q",
				slug, product.MinimumAgeBand, MinimumAgeBandChild, MinimumAgeBandTeen, MinimumAgeBandAdult)
		}
	}
	return nil
}

// canonicalized returns a copy whose slugs and bands are normalized to the form
// the guard compares against, applied once at parse time so no lookup has to
// re-normalize on the auth hot path.
func (p ProjectProductsConfig) canonicalized() ProjectProductsConfig {
	if len(p) == 0 {
		return nil
	}
	out := make(ProjectProductsConfig, len(p))
	for slug, product := range p {
		out[normalizeProductSlug(slug)] = ProjectProductConfig{
			MinimumAgeBand: normalizeProductSlug(product.MinimumAgeBand),
		}
	}
	return out
}

// minimumAgeBand returns the minimum band configured for slug, or "" when the
// product is unconfigured or imposes no restriction. slug must already be
// normalized (the product middleware does it once per request).
func (p ProjectProductsConfig) minimumAgeBand(slug string) string {
	return p[slug].MinimumAgeBand
}

// normalizeProductSlug trims and lower-cases a slug or band string so config
// authored as "Hold" / " TEEN " matches a header sent as "hold" / a band
// constant. Shared by slugs and bands because both are case-insensitive
// identifiers with the same normalization rule.
func normalizeProductSlug(raw string) string {
	return strings.TrimSpace(strings.ToLower(raw))
}

// ProjectCORSConfig is the per-project CORS policy. AllowedOrigins is layered
// on top of the global GATEWAY_ALLOWED_ORIGINS floor: a browser origin is
// accepted when it is in either set. Each entry must be a bare scheme+host(+port)
// origin (no path/query/fragment, lower-case http:// or https:// scheme); the
// project resolver validates them with middleware.ParseAllowedOrigins before
// they reach a request.
type ProjectCORSConfig struct {
	AllowedOrigins []string `json:"allowed_origins"`
}

// ParseProjectConfig decodes a project's config_json into the typed
// ProjectConfig. An empty or all-whitespace blob is the zero config (no
// per-project overrides) — the same meaning the store gives "" by normalising
// it to "{}". A malformed blob is a configuration error the caller must
// surface, never silently swallow.
func ParseProjectConfig(configJSON string) (ProjectConfig, error) {
	var cfg ProjectConfig
	if strings.TrimSpace(configJSON) == "" {
		return cfg, nil
	}
	dec := json.NewDecoder(strings.NewReader(configJSON))
	if err := dec.Decode(&cfg); err != nil {
		return ProjectConfig{}, fmt.Errorf("parse project config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return ProjectConfig{}, fmt.Errorf("parse project config: %w", err)
	}
	// Normalize the access allowlist to canonical comparison form AFTER
	// validation, so every downstream copy of the config (resolver scope, native
	// login, admin reads) matches a canonicalized login email like-against-like.
	cfg.Access = cfg.Access.canonicalized()
	// Same reason for the product slugs and their minimum bands: the guard
	// compares against the slug an X-Product header carried, normalized once here.
	cfg.Products = cfg.Products.canonicalized()
	return cfg, nil
}
