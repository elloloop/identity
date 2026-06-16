package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Default Sign in with Apple endpoints. Overridable via AppleConfig for
// tests.
const (
	appleAuthorizationURL = "https://appleid.apple.com/auth/authorize"
	appleTokenURL         = "https://appleid.apple.com/auth/token" // #nosec G101 -- OAuth token endpoint, not a credential.
	appleJWKSURL          = "https://appleid.apple.com/auth/keys"
	appleIssuer           = "https://appleid.apple.com"

	// appleClientSecretTTL bounds the lifetime of the ES256 client_secret
	// JWT we mint for the token endpoint. Apple permits up to six months;
	// we use a conservative short window since we mint one per exchange.
	appleClientSecretTTL = 5 * time.Minute
)

// AppleConfig configures a Sign in with Apple Exchanger.
//
// Apple does not issue a long-lived client secret. Instead the operator
// registers a Services ID (ClientID), an App ID team (TeamID), and a
// private signing key (KeyID + PrivateKeyPEM). The exchanger mints a
// short-lived ES256-signed client_secret JWT per code exchange.
type AppleConfig struct {
	// ClientID is the Apple Services ID (the OAuth client_id / `aud`
	// the token endpoint expects in the client secret, and the audience
	// of the returned id_token).
	ClientID string

	// TeamID is the Apple Developer team identifier; it is the `iss`
	// claim of the client secret JWT.
	TeamID string

	// KeyID is the identifier of the registered private key; it is the
	// `kid` header of the client secret JWT.
	KeyID string

	// PrivateKeyPEM is the PEM-encoded PKCS#8 EC private key downloaded
	// from the Apple developer portal, used to sign the client secret.
	PrivateKeyPEM string

	HTTPClient *http.Client

	// AuthorizationURL overrides the authorization endpoint. Optional.
	AuthorizationURL string
	// TokenURL overrides the token endpoint. Optional.
	TokenURL string
	// JWKSURL overrides the JWKS endpoint. Optional.
	JWKSURL string
	// Issuer overrides the expected id_token `iss`. Optional.
	Issuer string

	JWKSCacheTTL time.Duration
	Now          func() time.Time
}

type appleExchanger struct {
	cfg    AppleConfig
	priv   *ecdsa.PrivateKey
	client *http.Client
	jwks   *jwksCache
}

// NewApple returns an Exchanger for Sign in with Apple.
//
// The PrivateKeyPEM is parsed eagerly: if it is malformed, every
// Exchange / AuthorizationURL call returns ErrCodeExchangeFailed so a
// misconfiguration surfaces deterministically rather than at signing
// time. (buildOAuthRegistry only registers Apple when the credentials
// are present, so a parse failure is an operator error worth failing on.)
func NewApple(cfg AppleConfig) Exchanger {
	if cfg.TokenURL == "" {
		cfg.TokenURL = appleTokenURL
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = appleJWKSURL
	}
	if cfg.AuthorizationURL == "" {
		cfg.AuthorizationURL = appleAuthorizationURL
	}
	if cfg.Issuer == "" {
		cfg.Issuer = appleIssuer
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
	priv, _ := parseECPrivateKeyPEM(cfg.PrivateKeyPEM)
	return &appleExchanger{
		cfg:    cfg,
		priv:   priv,
		client: client,
		jwks:   newJWKSCache(cfg.JWKSURL, cfg.JWKSCacheTTL, client),
	}
}

func parseECPrivateKeyPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(pemStr) == "" {
		return nil, fmt.Errorf("%w: apple private key not configured", ErrCodeExchangeFailed)
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("%w: apple private key is not valid PEM", ErrCodeExchangeFailed)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fall back to SEC1 EC private keys for operators who supply a
		// raw "EC PRIVATE KEY" block.
		ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
		if ecErr != nil {
			return nil, fmt.Errorf("%w: parse apple private key: %w", ErrCodeExchangeFailed, err)
		}
		return ecKey, nil
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: apple private key is not an EC key", ErrCodeExchangeFailed)
	}
	return ecKey, nil
}

type appleTokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// appleIDClaims is the subset of an Apple id_token we consume. Apple
// emits email_verified and is_private_email as either JSON booleans or
// the strings "true"/"false", so we decode them leniently.
type appleIDClaims struct {
	Sub            string          `json:"sub"`
	Email          string          `json:"email"`
	EmailVerified  appleBoolString `json:"email_verified"`
	IsPrivateEmail appleBoolString `json:"is_private_email"`
}

// appleBoolString decodes a value that Apple may send as a JSON bool or
// a quoted "true"/"false" string.
type appleBoolString bool

func (b *appleBoolString) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	switch s {
	case "true":
		*b = true
	case "false", "", "null":
		*b = false
	default:
		return fmt.Errorf("apple: invalid bool value %q", s)
	}
	return nil
}

func (a *appleExchanger) Exchange(ctx context.Context, code, redirectURI string) (*Identity, error) {
	if code == "" {
		return nil, fmt.Errorf("%w: missing authorization code", ErrCodeExchangeFailed)
	}
	if a.cfg.ClientID == "" || a.cfg.TeamID == "" || a.cfg.KeyID == "" {
		return nil, fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}
	if a.priv == nil {
		return nil, fmt.Errorf("%w: apple signing key not configured", ErrCodeExchangeFailed)
	}

	clientSecret, err := a.clientSecret()
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", a.cfg.ClientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")
	if codeVerifier := codeVerifierFromContext(ctx); codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.TokenURL,
		strings.NewReader(form.Encode()))
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
	var tr appleTokenResponse
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

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("%w: missing email", ErrIdentityVerification)
	}
	if !bool(claims.EmailVerified) {
		return nil, fmt.Errorf("%w: %s", ErrEmailNotVerified, email)
	}

	// Apple delivers the user's display name only once, in the form_post
	// `user` field of the first authorization callback — never in the
	// id_token. The hosted callback captures it and threads it through
	// the context so first-login name capture works end-to-end.
	name := appleNameFromContext(ctx)

	return &Identity{
		ProviderUserID: claims.Sub,
		Email:          email,
		EmailVerified:  true,
		Name:           name,
		Provider:       "apple",
	}, nil
}

func (a *appleExchanger) AuthorizationURL(_ context.Context, redirectURI, state, codeChallenge string) (string, error) {
	if a.cfg.ClientID == "" {
		return "", fmt.Errorf("%w: client credentials not configured", ErrCodeExchangeFailed)
	}
	params := url.Values{}
	params.Set("client_id", a.cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", "openid email name")
	// Apple only returns email/name scopes via a form_post callback.
	params.Set("response_mode", "form_post")
	if err := addPKCEParams(params, state, codeChallenge); err != nil {
		return "", err
	}
	return buildAuthorizationURL(a.cfg.AuthorizationURL, params)
}

// clientSecret mints the short-lived ES256-signed JWT Apple's token
// endpoint expects in place of a static client_secret.
func (a *appleExchanger) clientSecret() (string, error) {
	now := a.cfg.Now()
	tok, err := jwt.NewBuilder().
		Issuer(a.cfg.TeamID).
		IssuedAt(now).
		Expiration(now.Add(appleClientSecretTTL)).
		Audience([]string{appleIssuer}).
		Subject(a.cfg.ClientID).
		Build()
	if err != nil {
		return "", fmt.Errorf("%w: build client secret: %w", ErrCodeExchangeFailed, err)
	}
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, a.cfg.KeyID); err != nil {
		return "", fmt.Errorf("%w: set kid: %w", ErrCodeExchangeFailed, err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, a.priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("%w: sign client secret: %w", ErrCodeExchangeFailed, err)
	}
	return string(signed), nil
}

func (a *appleExchanger) verifyIDToken(ctx context.Context, raw string) (*appleIDClaims, error) {
	set, err := a.jwks.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: jwks: %w", ErrIdentityVerification, err)
	}

	payload, err := verifyJWSWithAlgs(raw, set, jwa.ES256)
	if err != nil {
		a.jwks.Invalidate()
		set2, fErr := a.jwks.Get(ctx)
		if fErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
		}
		payload, err = verifyJWSWithAlgs(raw, set2, jwa.ES256)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
		}
	}

	tok, err := jwt.Parse(payload, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrIdentityVerification, err)
	}
	if iss := tok.Issuer(); iss != a.cfg.Issuer {
		return nil, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, iss)
	}
	if !containsString(tok.Audience(), a.cfg.ClientID) {
		return nil, fmt.Errorf("%w: bad aud", ErrIdentityVerification)
	}
	now := a.cfg.Now()
	if exp := tok.Expiration(); !exp.IsZero() && now.After(exp) {
		return nil, fmt.Errorf("%w: token expired", ErrIdentityVerification)
	}
	if iat := tok.IssuedAt(); !iat.IsZero() && iat.After(now.Add(2*time.Minute)) {
		return nil, fmt.Errorf("%w: iat in the future", ErrIdentityVerification)
	}

	var claims appleIDClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %w", ErrIdentityVerification, err)
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrIdentityVerification)
	}
	return &claims, nil
}
