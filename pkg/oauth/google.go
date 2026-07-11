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

// Default Google OIDC endpoints. Overridable via GoogleConfig for
// tests.
const (
	googleAuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL         = "https://oauth2.googleapis.com/token" // #nosec G101 -- OAuth token endpoint, not a credential.
	googleJWKSURL          = "https://www.googleapis.com/oauth2/v3/certs"
	googleIssuer           = "https://accounts.google.com"
)

// GoogleConfig configures a Google Exchanger. ClientID and
// ClientSecret are required; the rest default to the live Google
// endpoints and a 1h JWKS cache.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string

	// Prompt is the OAuth `prompt` value sent on the authorization request
	// (e.g. "select_account" to force the account chooser). Empty omits it,
	// falling back to Google's default behaviour.
	Prompt string

	// HTTPClient overrides the http.Client used for token + JWKS
	// requests. Optional; defaults to a 10s-timeout client.
	HTTPClient *http.Client

	// TokenURL overrides the token endpoint. Optional; defaults to
	// googleTokenURL.
	TokenURL string

	// AuthorizationURL overrides the provider authorization endpoint.
	// Optional; defaults to googleAuthorizationURL or the discovery
	// document's authorization_endpoint when DiscoveryURL is set.
	AuthorizationURL string

	// JWKSURL overrides the JWKS endpoint. Optional; defaults to
	// googleJWKSURL.
	JWKSURL string

	// DiscoveryURL overrides the OIDC discovery endpoint. When set,
	// Exchange resolves token / JWKS / userinfo endpoints from it.
	DiscoveryURL string

	// UserinfoURL overrides the OIDC userinfo endpoint. Optional.
	UserinfoURL string

	// Issuer overrides the expected `iss` claim. Optional; defaults
	// to googleIssuer.
	Issuer string

	// JWKSCacheTTL overrides the JWKS cache TTL. Optional; defaults
	// to 1h.
	JWKSCacheTTL time.Duration

	// Now overrides the clock used for ID token expiry validation.
	// Optional; defaults to time.Now.
	Now func() time.Time
}

type googleExchanger struct {
	cfg    GoogleConfig
	client *http.Client
	jwks   *jwksCache
}

// NewGoogle returns an Exchanger for Google OIDC.
func NewGoogle(cfg GoogleConfig) Exchanger {
	if cfg.TokenURL == "" {
		cfg.TokenURL = googleTokenURL
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = googleJWKSURL
	}
	if cfg.Issuer == "" {
		cfg.Issuer = googleIssuer
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
	return &googleExchanger{
		cfg:    cfg,
		client: client,
		jwks:   newJWKSCache(cfg.JWKSURL, cfg.JWKSCacheTTL, client),
	}
}

func (g *googleExchanger) Exchange(ctx context.Context, params ExchangeParams) (*Identity, error) {
	if params.Code == "" {
		return nil, fmt.Errorf("%w: missing authorization code", ErrCodeExchangeFailed)
	}
	if g.cfg.ClientID == "" || g.cfg.ClientSecret == "" {
		return nil, fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}

	tokenURL := g.cfg.TokenURL
	jwksURL := g.cfg.JWKSURL
	userinfoURL := g.cfg.UserinfoURL
	if g.cfg.DiscoveryURL != "" {
		doc, err := fetchOIDCDiscovery(ctx, g.client, g.cfg.DiscoveryURL)
		if err != nil {
			return nil, err
		}
		tokenURL = doc.TokenEndpoint
		jwksURL = doc.JWKSURI
		if userinfoURL == "" {
			userinfoURL = doc.UserinfoEndpoint
		}
	}
	if tokenURL == "" {
		tokenURL = googleTokenURL
	}
	if jwksURL == "" {
		jwksURL = googleJWKSURL
	}
	if g.jwks == nil || g.jwks.url != jwksURL {
		g.jwks = newJWKSCache(jwksURL, g.cfg.JWKSCacheTTL, g.client)
	}

	tr, err := oidcTokenExchange(ctx, g.client, tokenURL, codeExchangeForm(g.cfg.ClientID, g.cfg.ClientSecret, params))
	if err != nil {
		return nil, err
	}

	claims, err := g.verifyIDToken(ctx, tr.IDToken)
	if err != nil {
		return nil, err
	}

	if !claims.EmailVerified {
		return nil, fmt.Errorf("%w: %s", ErrEmailNotVerified, claims.Email)
	}

	userinfo, err := fetchOIDCUserInfo(ctx, g.client, userinfoURL, tr.AccessToken)
	if err != nil {
		return nil, err
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	name := claims.Name
	avatarURL := claims.Picture
	if userinfo != nil {
		if email == "" && userinfo.Email != "" {
			email = strings.ToLower(strings.TrimSpace(userinfo.Email))
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
	if email == "" {
		return nil, fmt.Errorf("%w: missing email", ErrIdentityVerification)
	}

	return &Identity{
		ProviderUserID: claims.Sub,
		Email:          email,
		EmailVerified:  true,
		Name:           name,
		AvatarURL:      avatarURL,
		Provider:       "google",
	}, nil
}

func (g *googleExchanger) AuthorizationURL(ctx context.Context, redirectURI, state, codeChallenge string) (string, error) {
	if g.cfg.ClientID == "" {
		return "", fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}
	authURL := g.cfg.AuthorizationURL
	if g.cfg.DiscoveryURL != "" && authURL == "" {
		doc, err := fetchOIDCDiscovery(ctx, g.client, g.cfg.DiscoveryURL)
		if err != nil {
			return "", err
		}
		authURL = doc.AuthorizationEndpoint
	}
	if authURL == "" {
		authURL = googleAuthorizationURL
	}

	params := url.Values{}
	params.Set("client_id", g.cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	if g.cfg.Prompt != "" {
		params.Set("prompt", g.cfg.Prompt)
	}
	if err := addPKCEParams(params, state, codeChallenge); err != nil {
		return "", err
	}
	return buildAuthorizationURL(authURL, params)
}

// googleIDClaims is the subset of an OIDC ID token we consume.
type googleIDClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// verifyIDToken verifies the signature, issuer, audience, and
// expiry of a Google-issued ID token, then returns its claims.
func (g *googleExchanger) verifyIDToken(ctx context.Context, raw string) (*googleIDClaims, error) {
	payload, tok, err := parseVerifiedIDToken(ctx, g.jwks, raw, jwa.RS256)
	if err != nil {
		return nil, err
	}

	// Google stamps the issuer with or without the https:// scheme; both
	// historical forms are accepted.
	if iss := tok.Issuer(); iss != g.cfg.Issuer && iss != strings.TrimPrefix(g.cfg.Issuer, "https://") {
		return nil, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, iss)
	}
	if err := checkAudience(tok, g.cfg.ClientID); err != nil {
		return nil, err
	}
	if err := checkTokenTimes(tok, g.cfg.Now()); err != nil {
		return nil, err
	}

	var claims googleIDClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %w", ErrIdentityVerification, err)
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrIdentityVerification)
	}
	if claims.Email == "" {
		return nil, fmt.Errorf("%w: missing email", ErrIdentityVerification)
	}
	return &claims, nil
}
