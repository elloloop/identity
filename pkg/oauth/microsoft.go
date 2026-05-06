package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Default Microsoft Azure AD common-endpoint URLs.
const (
	microsoftAuthorizationFormat = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	microsoftTokenURL     = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	microsoftJWKSURL      = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	microsoftIssuerFormat = "https://login.microsoftonline.com/%s/v2.0"
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
	// endpoint when AuthorizationURL is not set. Optional; defaults to
	// "common".
	TenantID string

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
		cfg.TokenURL = microsoftTokenURL
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

type microsoftTokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
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

	// Optional verification hint. Microsoft does not always emit
	// this; absence is treated as verified (the OIDC token issuance
	// itself implies a verified account in this flow).
	VerifiedEmail *bool `json:"verified_email"`
}

func (m *microsoftExchanger) Exchange(ctx context.Context, code, redirectURI string) (*Identity, error) {
	if code == "" {
		return nil, fmt.Errorf("%w: missing authorization code", ErrCodeExchangeFailed)
	}
	if m.cfg.ClientID == "" || m.cfg.ClientSecret == "" {
		return nil, fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", m.cfg.ClientID)
	form.Set("client_secret", m.cfg.ClientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")
	form.Set("scope", "openid email profile")
	if codeVerifier := codeVerifierFromContext(ctx); codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrCodeExchangeFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCodeExchangeFailed, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrCodeExchangeFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: provider HTTP %d", ErrCodeExchangeFailed, resp.StatusCode)
	}
	var tr microsoftTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("%w: parse response: %v", ErrCodeExchangeFailed, err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchangeFailed, tr.Error)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("%w: provider returned no id_token", ErrCodeExchangeFailed)
	}

	claims, err := m.verifyIDToken(ctx, tr.IDToken)
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

func (m *microsoftExchanger) verifyIDToken(ctx context.Context, raw string) (*microsoftIDClaims, error) {
	set, err := m.jwks.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: jwks: %v", ErrIdentityVerification, err)
	}

	payload, err := verifyJWS(raw, set)
	if err != nil {
		m.jwks.Invalidate()
		set2, fErr := m.jwks.Get(ctx)
		if fErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrIdentityVerification, err)
		}
		payload, err = verifyJWS(raw, set2)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrIdentityVerification, err)
		}
	}

	tok, err := jwt.Parse(payload, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %v", ErrIdentityVerification, err)
	}

	var claims microsoftIDClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %v", ErrIdentityVerification, err)
	}
	if claims.TID == "" {
		return nil, fmt.Errorf("%w: missing tid", ErrIdentityVerification)
	}
	expectedIss := fmt.Sprintf(m.cfg.IssuerFormat, claims.TID)
	if iss := tok.Issuer(); iss != expectedIss {
		return nil, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, iss)
	}
	auds := tok.Audience()
	if !containsString(auds, m.cfg.ClientID) {
		return nil, fmt.Errorf("%w: bad aud", ErrIdentityVerification)
	}
	now := m.cfg.Now()
	if exp := tok.Expiration(); !exp.IsZero() && now.After(exp) {
		return nil, fmt.Errorf("%w: token expired", ErrIdentityVerification)
	}
	if iat := tok.IssuedAt(); !iat.IsZero() && iat.After(now.Add(2*time.Minute)) {
		return nil, fmt.Errorf("%w: iat in the future", ErrIdentityVerification)
	}
	return &claims, nil
}
