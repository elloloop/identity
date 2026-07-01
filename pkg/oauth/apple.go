package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	appleAuthorizationURL = "https://appleid.apple.com/auth/authorize"
	appleTokenURL         = "https://appleid.apple.com/auth/token" //nolint:gosec // this is a public URL, not a credential
	appleJWKSURL          = "https://appleid.apple.com/auth/keys"
	appleIssuer           = "https://appleid.apple.com"
)

// AppleConfig configures an Apple Exchanger. ClientID, TeamID,
// KeyID, and PrivateKey are required.
type AppleConfig struct {
	ClientID   string
	TeamID     string
	KeyID      string
	PrivateKey string

	TokenURL string
	JWKSURL  string
	Issuer   string

	HTTPClient   *http.Client
	JWKSCacheTTL time.Duration
	Now          func() time.Time
}

type appleExchanger struct {
	cfg    AppleConfig
	client *http.Client
	jwks   *jwksCache

	mu          sync.Mutex
	parsedKey   jwk.Key
	cachedToken string
	tokenExp    time.Time
}

// NewApple returns an Exchanger that implements Sign-In with Apple.
func NewApple(cfg AppleConfig) Exchanger {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = defaultHTTPClient()
	}
	if cfg.JWKSCacheTTL == 0 {
		cfg.JWKSCacheTTL = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = appleTokenURL
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = appleJWKSURL
	}
	if cfg.Issuer == "" {
		cfg.Issuer = appleIssuer
	}
	return &appleExchanger{
		cfg:    cfg,
		client: cfg.HTTPClient,
		jwks:   newJWKSCache(cfg.JWKSURL, cfg.JWKSCacheTTL, cfg.HTTPClient),
	}
}

func (a *appleExchanger) clientSecret() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.cfg.Now()
	if a.cachedToken != "" && now.Before(a.tokenExp) {
		return a.cachedToken, nil
	}

	if a.parsedKey == nil {
		pkBytes := []byte(strings.TrimSpace(a.cfg.PrivateKey))
		if !strings.HasPrefix(string(pkBytes), "-----BEGIN") {
			// Try base64 decoding if it doesn't look like PEM
			dec, err := base64.StdEncoding.DecodeString(string(pkBytes))
			if err == nil {
				pkBytes = dec
			}
		}

		key, err := jwk.ParseKey(pkBytes, jwk.WithPEM(true))
		if err != nil {
			return "", fmt.Errorf("parse private key: %w", err)
		}
		if err := key.Set(jwk.KeyIDKey, a.cfg.KeyID); err != nil {
			return "", err
		}
		a.parsedKey = key
	}

	exp := now.Add(5 * time.Minute)
	tok, err := jwt.NewBuilder().
		Issuer(a.cfg.TeamID).
		IssuedAt(now).
		Expiration(exp).
		Audience([]string{a.cfg.Issuer}).
		Subject(a.cfg.ClientID).
		Build()
	if err != nil {
		return "", fmt.Errorf("build client secret: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, a.parsedKey))
	if err != nil {
		return "", fmt.Errorf("sign client secret: %w", err)
	}

	a.cachedToken = string(signed)
	a.tokenExp = exp.Add(-30 * time.Second) // 30s buffer
	return a.cachedToken, nil
}

func (a *appleExchanger) AuthorizationURL(ctx context.Context, redirectURI, state, codeChallenge string) (string, error) {
	if a.cfg.ClientID == "" {
		return "", fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}

	params := url.Values{}
	params.Set("client_id", a.cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("response_mode", "form_post")
	params.Set("scope", "name email")
	if err := addPKCEParams(params, state, codeChallenge); err != nil {
		return "", err
	}
	return buildAuthorizationURL(appleAuthorizationURL, params)
}

func (a *appleExchanger) Exchange(ctx context.Context, params ExchangeParams) (*Identity, error) {
	if a.cfg.ClientID == "" || a.cfg.PrivateKey == "" {
		return nil, fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}

	secret, err := a.clientSecret()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCodeExchangeFailed, err)
	}

	form := url.Values{}
	form.Set("code", params.Code)
	form.Set("client_id", a.cfg.ClientID)
	form.Set("client_secret", secret)
	form.Set("redirect_uri", params.RedirectURI)
	form.Set("grant_type", "authorization_code")
	if params.CodeVerifier != "" {
		form.Set("code_verifier", params.CodeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrCodeExchangeFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
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

	var tr struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("%w: parse response: %w", ErrCodeExchangeFailed, err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchangeFailed, tr.Error)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("%w: provider returned no id_token", ErrCodeExchangeFailed)
	}

	claims, err := a.verifyIDToken(ctx, tr.IDToken)
	if err != nil {
		return nil, err
	}

	// verifyIDToken has already established a present, verified email; here
	// we only normalize it and (optionally) enrich the display name.
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return nil, fmt.Errorf("%w: missing email", ErrIdentityVerification)
	}

	name := claims.Name
	if params.AppleUserPayload != "" {
		var appleUser struct {
			Name struct {
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
			} `json:"name"`
		}
		if err := json.Unmarshal([]byte(params.AppleUserPayload), &appleUser); err == nil {
			first := strings.TrimSpace(appleUser.Name.FirstName)
			last := strings.TrimSpace(appleUser.Name.LastName)
			if first != "" || last != "" {
				name = strings.TrimSpace(first + " " + last)
			}
		}
	}

	return &Identity{
		ProviderUserID: claims.Sub,
		Email:          email,
		EmailVerified:  true,
		Name:           name,
		AvatarURL:      "",
		Provider:       "apple",
	}, nil
}

type appleIDClaims struct {
	Sub           string      `json:"sub"`
	Email         string      `json:"email"`
	EmailVerified interface{} `json:"email_verified"`
	Name          string      `json:"name"`
}

func (a *appleExchanger) verifyIDToken(ctx context.Context, raw string) (*appleIDClaims, error) {
	payload, err := verifyJWSWithRotation(ctx, a.jwks, raw, jwa.RS256)
	if err != nil {
		return nil, err
	}

	tok, err := jwt.Parse(payload, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrIdentityVerification, err)
	}
	if iss := tok.Issuer(); iss != a.cfg.Issuer {
		return nil, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, iss)
	}
	auds := tok.Audience()
	if !containsString(auds, a.cfg.ClientID) {
		return nil, fmt.Errorf("%w: bad aud", ErrIdentityVerification)
	}
	if err := checkTokenTimes(tok, a.cfg.Now()); err != nil {
		return nil, err
	}

	var claims appleIDClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %w", ErrIdentityVerification, err)
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrIdentityVerification)
	}
	if claims.Email == "" {
		return nil, fmt.Errorf("%w: missing email", ErrIdentityVerification)
	}
	if !appleEmailVerified(claims.EmailVerified) {
		return nil, fmt.Errorf("%w: email not verified: %s", ErrEmailNotVerified, claims.Email)
	}

	return &claims, nil
}
