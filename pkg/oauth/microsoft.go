package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

// Default Microsoft Azure AD common-endpoint URLs.
const (
	microsoftAuthorizationFormat = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	microsoftExchangeEndpoint    = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	microsoftJWKSURL             = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	microsoftIssuerFormat        = "https://login.microsoftonline.com/%s/v2.0"
)

// MicrosoftConfig configures a Microsoft Azure AD Exchanger.
type MicrosoftConfig struct {
	ClientID     string
	ClientSecret string

	HTTPClient *http.Client

	// AuthorizationURL overrides the authorization endpoint. Optional.
	AuthorizationURL string

	// TokenURL overrides the token endpoint. Optional.
	TokenURL string

	// JWKSURL overrides the JWKS endpoint. Optional.
	JWKSURL string

	// TenantID controls the default tenant segment in the authorization
	// endpoint when AuthorizationURL is not set, AND pins verification to a
	// single Azure AD directory: a token whose `tid` is not this value is
	// rejected. A meta value ("common"/"organizations"/"consumers") is a
	// multi-tenant marker and does NOT pin. Optional; empty/"common" keeps the
	// multi-tenant default.
	TenantID string

	// AllowedTenants is an allow-list of Azure AD directory (tenant) GUIDs:
	// when non-empty, a token whose `tid` is not a member is rejected. It is the
	// multi-tenant counterpart to the single TenantID pin — several trusted
	// tenants instead of exactly one. Azure always stamps `tid` as a directory
	// GUID, so entries must be GUIDs (matched case-insensitively); a
	// verified-domain string would never match and is rejected at config time.
	// Empty imposes no allow-list.
	AllowedTenants []string

	// IssuerFormat is a fmt.Sprintf format string into which the
	// token's `tid` (tenant id) claim is interpolated to derive the
	// expected issuer. Optional; defaults to the Microsoft format.
	// In tests, set this to e.g. "%s" plus a fixed test issuer.
	IssuerFormat string

	JWKSCacheTTL time.Duration
	Now          func() time.Time
}

type microsoftExchanger struct {
	cfg    MicrosoftConfig
	client *http.Client
	jwks   *jwksCache
}

// NewMicrosoft returns an Exchanger for Microsoft Azure AD.
func NewMicrosoft(cfg MicrosoftConfig) Exchanger {
	if cfg.TokenURL == "" {
		cfg.TokenURL = microsoftExchangeEndpoint
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = microsoftJWKSURL
	}
	if cfg.IssuerFormat == "" {
		cfg.IssuerFormat = microsoftIssuerFormat
	}
	if cfg.JWKSCacheTTL == 0 {
		cfg.JWKSCacheTTL = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	client := cfg.HTTPClient
	if client == nil {
		client = defaultHTTPClient()
	}
	return &microsoftExchanger{
		cfg:    cfg,
		client: client,
		jwks:   newJWKSCache(cfg.JWKSURL, cfg.JWKSCacheTTL, client),
	}
}

// microsoftIDClaims captures the subset of an MS ID token we use.
// MS tokens may carry email under "email", "preferred_username", or
// "upn"; we coalesce in that order.
type microsoftIDClaims struct {
	Sub               string `json:"sub"`
	OID               string `json:"oid"` // stable per-user ID across tenants
	TID               string `json:"tid"` // tenant id
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	UPN               string `json:"upn"`
	Name              string `json:"name"`
	Picture           string `json:"picture"`

	// VerifiedEmail is honored only as a NEGATIVE signal: when present and false
	// the email is rejected outright. A true value does NOT by itself authorize
	// trust — the nOAuth guard requires a tenant pin OR xms_edov (see
	// microsoftEmailTrusted).
	VerifiedEmail *bool `json:"verified_email"`

	// XMSEdov ("email domain owner verified") is Microsoft's polymorphic
	// assertion (JSON bool OR string "true"/"false") that the issuing tenant is
	// verified to own the email's domain. It is the claim that defends against
	// the nOAuth cross-tenant email-spoofing vector: on a multi-tenant token
	// (issuer derived from the token's own tid, no tenant pin) the email is
	// trusted for account federation ONLY when xms_edov is true — absent/false
	// leaves the email unverified.
	XMSEdov interface{} `json:"xms_edov"`
}

// microsoftTenantPin holds the deployment/project tenant-pinning inputs shared
// by the hosted exchanger and the native verifier. A configured single TenantID
// or a non-empty AllowedTenants list means the operator vouches for the
// issuing tenant(s), which is itself sufficient to trust the token's email.
type microsoftTenantPin struct {
	TenantID       string
	AllowedTenants []string
}

// microsoftMetaTenants are the Azure AD "meta" tenant segments that denote a
// MULTI-tenant configuration rather than a single directory. A real token's
// `tid` is always a concrete directory GUID, so treating one of these as a pin
// would reject every genuine token; they mean "no tenant pin" instead.
var microsoftMetaTenants = map[string]bool{"common": true, "organizations": true, "consumers": true}

// enforce checks a token's tid against the pin and reports whether the tenant
// was pinned. TenantID (a single directory) and AllowedTenants (a set) form the
// UNION of accepted tenants: when a pin is configured, tid is accepted if it
// equals TenantID OR is a member of AllowedTenants; matching either is enough.
// A configured pin that tid satisfies none of is a hard reject
// (ErrIdentityVerification). A meta TenantID ("common"/"organizations"/
// "consumers") is not a pin. pinned is true only when a real constraint was
// configured and satisfied — the signal that the deployment vouches for the
// issuing tenant. Azure stamps `tid` as a directory GUID; GUIDs are
// case-insensitive, so every comparison folds.
func (p microsoftTenantPin) enforce(tid string) (pinned bool, err error) {
	pinTenant := p.TenantID != "" && !microsoftMetaTenants[strings.ToLower(p.TenantID)]
	if !pinTenant && len(p.AllowedTenants) == 0 {
		// No real pin configured (empty, or only a meta TenantID) → multi-tenant.
		return false, nil
	}
	if pinTenant && strings.EqualFold(tid, p.TenantID) {
		return true, nil
	}
	if containsFold(p.AllowedTenants, tid) {
		return true, nil
	}
	return false, fmt.Errorf("%w: tenant not allowed", ErrIdentityVerification)
}

// containsFold reports whether needle case-insensitively equals any element of
// haystack (used for GUID membership, which is case-insensitive).
func containsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// microsoftEmailTrusted decides whether a Microsoft token's email may be
// treated as VERIFIED for account federation, the nOAuth guard applied
// identically by the hosted exchanger and the native verifier. The only
// legitimate proofs are: the issuing tenant is pinned (the deployment/project
// vouches for it), OR the token carries xms_edov==true (Microsoft asserts the
// tenant is verified to own the email's domain). A non-standard
// verified_email==true is deliberately NOT trusted on its own — an attacker
// tenant can set it just like the email itself; verified_email is honoured only
// as a NEGATIVE signal (an explicit false is rejected by the caller before this).
// When this returns false the email is unproven and the caller rejects it with
// ErrEmailNotVerified.
func microsoftEmailTrusted(pinned bool, claims *microsoftIDClaims) bool {
	return pinned || claimIsTrue(claims.XMSEdov)
}

func (m *microsoftExchanger) Exchange(ctx context.Context, params ExchangeParams) (*Identity, error) {
	if m.cfg.ClientID == "" || m.cfg.ClientSecret == "" {
		return nil, fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}

	// Microsoft requires the scope on the token request; the rest of the
	// authorization-code grant is the shared OIDC form.
	form := codeExchangeForm(m.cfg.ClientID, m.cfg.ClientSecret, params)
	form.Set("scope", "openid email profile")

	tr, err := oidcTokenExchange(ctx, m.client, m.cfg.TokenURL, form)
	if err != nil {
		return nil, err
	}

	claims, pinned, err := m.verifyIDToken(ctx, tr.IDToken)
	if err != nil {
		return nil, err
	}

	email := strings.TrimSpace(claims.Email)
	if email == "" {
		email = strings.TrimSpace(claims.PreferredUsername)
	}
	if email == "" {
		email = strings.TrimSpace(claims.UPN)
	}
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("%w: missing email", ErrIdentityVerification)
	}

	if claims.VerifiedEmail != nil && !*claims.VerifiedEmail {
		return nil, fmt.Errorf("%w: %s", ErrEmailNotVerified, email)
	}
	// nOAuth guard: a multi-tenant Microsoft token (issuer derived from its own
	// tid, no tenant pin) may carry any tenant-set email. Trust it as verified
	// only when the tenant is pinned, or xms_edov proves domain ownership.
	if !microsoftEmailTrusted(pinned, claims) {
		return nil, fmt.Errorf("%w: %s", ErrEmailNotVerified, email)
	}

	subject := claims.OID
	if subject == "" {
		subject = claims.Sub
	}
	if subject == "" {
		return nil, fmt.Errorf("%w: missing subject", ErrIdentityVerification)
	}

	return &Identity{
		ProviderUserID: subject,
		Email:          strings.ToLower(email),
		EmailVerified:  true,
		Name:           claims.Name,
		AvatarURL:      claims.Picture,
		Provider:       "microsoft",
	}, nil
}

func (m *microsoftExchanger) AuthorizationURL(_ context.Context, redirectURI, state, codeChallenge string) (string, error) {
	if m.cfg.ClientID == "" {
		return "", fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}
	authURL := m.cfg.AuthorizationURL
	if authURL == "" {
		tenant := strings.TrimSpace(m.cfg.TenantID)
		if tenant == "" {
			tenant = "common"
		}
		authURL = fmt.Sprintf(microsoftAuthorizationFormat, tenant)
	}

	params := url.Values{}
	params.Set("client_id", m.cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	if err := addPKCEParams(params, state, codeChallenge); err != nil {
		return "", err
	}
	return buildAuthorizationURL(authURL, params)
}

// verifyIDToken validates the ID token and returns the parsed claims plus
// whether the issuing tenant was pinned (a configured tenant_id or allow-list
// that the token's tid satisfied) — the caller folds pinned into the email-trust
// decision.
func (m *microsoftExchanger) verifyIDToken(ctx context.Context, raw string) (*microsoftIDClaims, bool, error) {
	payload, tok, err := parseVerifiedIDToken(ctx, m.jwks, raw, jwa.RS256)
	if err != nil {
		return nil, false, err
	}

	// Microsoft's issuer and tenant pin both derive from the token's own
	// `tid`, so the claims are decoded before the issuer check.
	var claims microsoftIDClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false, fmt.Errorf("%w: decode claims: %w", ErrIdentityVerification, err)
	}
	if claims.TID == "" {
		return nil, false, fmt.Errorf("%w: missing tid", ErrIdentityVerification)
	}
	pin := microsoftTenantPin{TenantID: m.cfg.TenantID, AllowedTenants: m.cfg.AllowedTenants}
	pinned, err := pin.enforce(claims.TID)
	if err != nil {
		return nil, false, err
	}
	expectedIss := fmt.Sprintf(m.cfg.IssuerFormat, claims.TID)
	if iss := tok.Issuer(); iss != expectedIss {
		return nil, false, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, iss)
	}
	if err := checkAudience(tok, m.cfg.ClientID); err != nil {
		return nil, false, err
	}
	if err := checkTokenTimes(tok, m.cfg.Now()); err != nil {
		return nil, false, err
	}
	return &claims, pinned, nil
}
