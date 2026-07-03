package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

// defaultOIDCScopes is the scope set requested when a generic OIDC
// provider config does not specify scopes.
var defaultOIDCScopes = []string{"openid", "email", "profile"}

// oidcAllowedAlgs is the set of id_token signature algorithms a generic
// OIDC provider may use. It is restricted to the asymmetric algorithms
// OIDC permits (RFC 7518) — symmetric (HS*) and "none" are refused so a
// provider's public JWKS can never be abused for an alg-substitution
// forgery.
var oidcAllowedAlgs = []jwa.SignatureAlgorithm{
	jwa.RS256, jwa.RS384, jwa.RS512,
	jwa.ES256, jwa.ES384, jwa.ES512,
	jwa.PS256, jwa.PS384, jwa.PS512,
}

// GenericOIDCConfig configures a config-driven OIDC Exchanger for an
// arbitrary standards-compliant provider (Okta, Auth0, Keycloak, any
// self-hosted issuer). It is the additive, code-release-free path: an
// operator enables a new provider purely via GATEWAY_OAUTH_OIDC_* env vars.
//
// IssuerURL is the provider's issuer (e.g. https://example.okta.com).
// The exchanger resolves the authorization / token / JWKS / userinfo
// endpoints from <IssuerURL>/.well-known/openid-configuration unless
// DiscoveryURL overrides it.
type GenericOIDCConfig struct {
	// ProviderKey is the registry key (e.g. "okta") this exchanger is
	// registered under and reported in Identity.Provider.
	ProviderKey string

	IssuerURL    string
	ClientID     string
	ClientSecret string

	// Scopes overrides the requested OAuth scopes. Optional; defaults
	// to "openid email profile". "openid" is always ensured.
	Scopes []string

	// DiscoveryURL overrides the well-known discovery endpoint. Optional;
	// derived from IssuerURL when empty.
	DiscoveryURL string

	HTTPClient *http.Client
	// DiscoveryCacheTTL bounds how long a fetched discovery document is
	// reused before re-fetching. Optional; defaults to one hour.
	DiscoveryCacheTTL time.Duration
	JWKSCacheTTL      time.Duration
	Now               func() time.Time
}

type oidcExchanger struct {
	cfg    GenericOIDCConfig
	client *http.Client

	// mu guards the cached discovery document and the JWKS cache it
	// points at. A single *oidcExchanger serves all logins for its
	// provider, so the lazy first-resolution must be synchronized.
	mu    sync.Mutex
	doc   *oidcDiscoveryDocument
	docAt time.Time
	jwks  *jwksCache
}

// NewOIDC returns a generic OIDC Exchanger built on the shared OIDC
// discovery / userinfo / JWKS helpers. ProviderKey, IssuerURL (or
// DiscoveryURL), ClientID, and ClientSecret are required.
func NewOIDC(cfg GenericOIDCConfig) Exchanger {
	if cfg.DiscoveryURL == "" && cfg.IssuerURL != "" {
		cfg.DiscoveryURL = strings.TrimRight(cfg.IssuerURL, "/") +
			"/.well-known/openid-configuration"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = defaultOIDCScopes
	}
	if cfg.DiscoveryCacheTTL == 0 {
		cfg.DiscoveryCacheTTL = time.Hour
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
	return &oidcExchanger{cfg: cfg, client: client}
}

func (o *oidcExchanger) providerKey() string {
	if o.cfg.ProviderKey != "" {
		return o.cfg.ProviderKey
	}
	return "oidc"
}

func (o *oidcExchanger) scopeString() string {
	scopes := o.cfg.Scopes
	hasOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		scopes = append([]string{"openid"}, scopes...)
	}
	return strings.Join(scopes, " ")
}

// resolve returns the provider's discovery document and a JWKS cache for
// its signing keys, fetching the discovery document at most once per
// DiscoveryCacheTTL. It serializes concurrent first-time resolution so a
// single shared exchanger is safe for many in-flight logins, and serves a
// stale document if a refresh fails transiently.
func (o *oidcExchanger) resolve(ctx context.Context) (*oidcDiscoveryDocument, *jwksCache, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.doc != nil && o.cfg.Now().Sub(o.docAt) < o.cfg.DiscoveryCacheTTL {
		return o.doc, o.jwks, nil
	}

	doc, err := fetchOIDCDiscovery(ctx, o.client, o.cfg.DiscoveryURL)
	if err != nil {
		if o.doc != nil {
			return o.doc, o.jwks, nil
		}
		return nil, nil, err
	}

	// OIDC Discovery 4.3: the issuer advertised by the discovery document
	// MUST match the issuer we configured (from which the well-known URL
	// derives). Skipped when only an explicit DiscoveryURL is configured,
	// since no expected issuer is known.
	if o.cfg.IssuerURL != "" && !sameIssuer(doc.Issuer, o.cfg.IssuerURL) {
		return nil, nil, fmt.Errorf("%w: discovery issuer %q does not match configured issuer",
			ErrCodeExchangeFailed, doc.Issuer)
	}

	if o.jwks == nil || o.jwks.url != doc.JWKSURI {
		o.jwks = newJWKSCache(doc.JWKSURI, o.cfg.JWKSCacheTTL, o.client)
	}
	o.doc = doc
	o.docAt = o.cfg.Now()
	return o.doc, o.jwks, nil
}

// sameIssuer compares two issuer URLs, tolerating a trailing slash on
// either side.
func sameIssuer(a, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}

func (o *oidcExchanger) AuthorizationURL(ctx context.Context, redirectURI, state, codeChallenge string) (string, error) {
	if o.cfg.ClientID == "" {
		return "", fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}
	doc, _, err := o.resolve(ctx)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(doc.AuthorizationEndpoint) == "" {
		return "", fmt.Errorf("%w: discovery document missing authorization_endpoint", ErrCodeExchangeFailed)
	}

	params := url.Values{}
	params.Set("client_id", o.cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", o.scopeString())
	if err := addPKCEParams(params, state, codeChallenge); err != nil {
		return "", err
	}
	return buildAuthorizationURL(doc.AuthorizationEndpoint, params)
}

func (o *oidcExchanger) Exchange(ctx context.Context, params ExchangeParams) (*Identity, error) {
	if params.Code == "" {
		return nil, fmt.Errorf("%w: missing authorization code", ErrCodeExchangeFailed)
	}
	if o.cfg.ClientID == "" || o.cfg.ClientSecret == "" {
		return nil, fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}

	doc, jwks, err := o.resolve(ctx)
	if err != nil {
		return nil, err
	}

	tr, err := oidcTokenExchange(ctx, o.client, doc.TokenEndpoint, codeExchangeForm(o.cfg.ClientID, o.cfg.ClientSecret, params))
	if err != nil {
		return nil, err
	}

	claims, err := o.verifyIDToken(ctx, jwks, tr.IDToken, doc.Issuer)
	if err != nil {
		return nil, err
	}

	// The email and its verified flag MUST come from the same source. We
	// trust the id_token's email together with its own email_verified; we
	// never let a userinfo verified flag vouch for a different address (a
	// matching sub only proves same user, not same address). userinfo is a
	// best-effort gap-filler: fetched only when the id_token lacks the
	// email or a display name, and — once an email is established — its
	// failure is non-fatal.
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	emailVerified := claims.EmailVerified != nil && *claims.EmailVerified
	name := strings.TrimSpace(claims.Name)
	avatarURL := strings.TrimSpace(claims.Picture)

	if email == "" || name == "" {
		userinfo, uErr := fetchOIDCUserInfo(ctx, o.client, doc.UserinfoEndpoint, tr.AccessToken)
		switch {
		case uErr != nil && email == "":
			// No email in the id_token and userinfo is unavailable — we
			// cannot establish a verified address, so the login fails.
			return nil, uErr
		case uErr != nil:
			// The id_token already supplied the email; userinfo was only a
			// best-effort source for the display name. Proceed without it.
		case userinfo != nil:
			// OIDC Core 5.3.2: the userinfo sub MUST match the id_token sub
			// before any of its fields are trusted.
			if userinfo.Sub != "" && userinfo.Sub != claims.Sub {
				return nil, fmt.Errorf("%w: userinfo sub does not match id_token sub", ErrIdentityVerification)
			}
			if email == "" && userinfo.Email != "" {
				// Email AND its verified flag both come from userinfo.
				email = strings.ToLower(strings.TrimSpace(userinfo.Email))
				emailVerified = userinfo.EmailVerified != nil && *userinfo.EmailVerified
			}
			if name == "" {
				name = strings.TrimSpace(userinfo.Name)
			}
			if name == "" {
				name = strings.TrimSpace(userinfo.PreferredUsername)
			}
			if avatarURL == "" {
				avatarURL = strings.TrimSpace(userinfo.Picture)
			}
		}
	}

	if email == "" {
		return nil, fmt.Errorf("%w: missing email", ErrIdentityVerification)
	}
	if !emailVerified {
		return nil, fmt.Errorf("%w: %s", ErrEmailNotVerified, email)
	}

	return &Identity{
		ProviderUserID: claims.Sub,
		Email:          email,
		EmailVerified:  true,
		Name:           name,
		AvatarURL:      avatarURL,
		Provider:       o.providerKey(),
	}, nil
}

// oidcIDClaims is the subset of a generic OIDC id_token we consume.
type oidcIDClaims struct {
	Sub           string `json:"sub"`
	Azp           string `json:"azp"`
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (o *oidcExchanger) verifyIDToken(ctx context.Context, jwks *jwksCache, raw, issuer string) (*oidcIDClaims, error) {
	payload, tok, err := parseVerifiedIDToken(ctx, jwks, raw, oidcAllowedAlgs...)
	if err != nil {
		return nil, err
	}

	var claims oidcIDClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %w", ErrIdentityVerification, err)
	}

	if iss := tok.Issuer(); iss != issuer {
		return nil, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, iss)
	}
	if err := checkAudience(tok, o.cfg.ClientID); err != nil {
		return nil, err
	}
	// OIDC Core 3.1.3.7: when the token carries multiple audiences, the
	// authorized party (azp) MUST be present and equal to our client_id.
	if auds := tok.Audience(); len(auds) > 1 && claims.Azp != o.cfg.ClientID {
		return nil, fmt.Errorf("%w: azp does not match client_id for multi-audience token", ErrIdentityVerification)
	}
	now := o.cfg.Now()
	// exp is REQUIRED (OIDC Core 2). A token without it would never expire,
	// so refuse it rather than treating expiry as optional.
	exp := tok.Expiration()
	if exp.IsZero() {
		return nil, fmt.Errorf("%w: missing exp", ErrIdentityVerification)
	}
	if now.After(exp) {
		return nil, fmt.Errorf("%w: token expired", ErrIdentityVerification)
	}
	// iat is also REQUIRED (OIDC Core 2).
	iat := tok.IssuedAt()
	if iat.IsZero() {
		return nil, fmt.Errorf("%w: missing iat", ErrIdentityVerification)
	}
	if iat.After(now.Add(2 * time.Minute)) {
		return nil, fmt.Errorf("%w: iat in the future", ErrIdentityVerification)
	}

	if claims.Sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrIdentityVerification)
	}
	return &claims, nil
}
