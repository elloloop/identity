package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// defaultOIDCScopes is the scope set requested when a generic OIDC
// provider config does not specify scopes.
var defaultOIDCScopes = []string{"openid", "email", "profile"}

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

	HTTPClient   *http.Client
	JWKSCacheTTL time.Duration
	Now          func() time.Time
}

type oidcExchanger struct {
	cfg    GenericOIDCConfig
	client *http.Client
	jwks   *jwksCache
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

type oidcTokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func (o *oidcExchanger) AuthorizationURL(ctx context.Context, redirectURI, state, codeChallenge string) (string, error) {
	if o.cfg.ClientID == "" {
		return "", fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}
	doc, err := fetchOIDCDiscovery(ctx, o.client, o.cfg.DiscoveryURL)
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

	doc, err := fetchOIDCDiscovery(ctx, o.client, o.cfg.DiscoveryURL)
	if err != nil {
		return nil, err
	}
	if o.jwks == nil || o.jwks.url != doc.JWKSURI {
		o.jwks = newJWKSCache(doc.JWKSURI, o.cfg.JWKSCacheTTL, o.client)
	}

	form := url.Values{}
	form.Set("code", params.Code)
	form.Set("client_id", o.cfg.ClientID)
	form.Set("client_secret", o.cfg.ClientSecret)
	form.Set("redirect_uri", params.RedirectURI)
	form.Set("grant_type", "authorization_code")
	if params.CodeVerifier != "" {
		form.Set("code_verifier", params.CodeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrCodeExchangeFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCodeExchangeFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrCodeExchangeFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: provider HTTP %d", ErrCodeExchangeFailed, resp.StatusCode)
	}
	var tr oidcTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("%w: parse response: %w", ErrCodeExchangeFailed, err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchangeFailed, tr.Error)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("%w: provider returned no id_token", ErrCodeExchangeFailed)
	}

	claims, err := o.verifyIDToken(ctx, tr.IDToken, doc.Issuer)
	if err != nil {
		return nil, err
	}

	userinfo, err := fetchOIDCUserInfo(ctx, o.client, doc.UserinfoEndpoint, tr.AccessToken)
	if err != nil {
		return nil, err
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	emailVerified := claims.EmailVerified != nil && *claims.EmailVerified
	name := strings.TrimSpace(claims.Name)
	avatarURL := strings.TrimSpace(claims.Picture)
	if userinfo != nil {
		if email == "" && userinfo.Email != "" {
			email = strings.ToLower(strings.TrimSpace(userinfo.Email))
		}
		if !emailVerified && userinfo.EmailVerified != nil && *userinfo.EmailVerified {
			emailVerified = true
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
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (o *oidcExchanger) verifyIDToken(ctx context.Context, raw, issuer string) (*oidcIDClaims, error) {
	set, err := o.jwks.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: jwks: %w", ErrIdentityVerification, err)
	}

	payload, err := verifyJWS(raw, set)
	if err != nil && errors.Is(err, errKeyNotFound) {
		o.jwks.Invalidate()
		set2, fErr := o.jwks.Get(ctx)
		if fErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
		}
		payload, err = verifyJWS(raw, set2)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
	}

	tok, err := jwt.Parse(payload, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrIdentityVerification, err)
	}
	if iss := tok.Issuer(); iss != issuer {
		return nil, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, iss)
	}
	if !containsString(tok.Audience(), o.cfg.ClientID) {
		return nil, fmt.Errorf("%w: bad aud", ErrIdentityVerification)
	}
	now := o.cfg.Now()
	if exp := tok.Expiration(); !exp.IsZero() && now.After(exp) {
		return nil, fmt.Errorf("%w: token expired", ErrIdentityVerification)
	}
	if iat := tok.IssuedAt(); !iat.IsZero() && iat.After(now.Add(2*time.Minute)) {
		return nil, fmt.Errorf("%w: iat in the future", ErrIdentityVerification)
	}

	var claims oidcIDClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %w", ErrIdentityVerification, err)
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrIdentityVerification)
	}
	return &claims, nil
}
