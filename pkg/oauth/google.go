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

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
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

// tokenResponse is the subset of a Google token response we care
// about. We only consume `id_token`; the access_token / refresh_token
// fields are intentionally discarded — Identity does not store
// provider tokens for ongoing API access.
type googleTokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func (g *googleExchanger) Exchange(ctx context.Context, code, redirectURI string) (*Identity, error) {
	if code == "" {
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

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", g.cfg.ClientID)
	form.Set("client_secret", g.cfg.ClientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")
	if codeVerifier := codeVerifierFromContext(ctx); codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrCodeExchangeFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
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
	var tr googleTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("%w: parse response: %w", ErrCodeExchangeFailed, err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchangeFailed, tr.Error)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("%w: provider returned no id_token", ErrCodeExchangeFailed)
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
	set, err := g.jwks.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: jwks: %w", ErrIdentityVerification, err)
	}

	payload, err := verifyJWS(raw, set)
	if err != nil {
		// On verification failure we may be looking at a stale cache
		// after a key rotation. Invalidate and try once more.
		g.jwks.Invalidate()
		set2, fErr := g.jwks.Get(ctx)
		if fErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
		}
		payload, err = verifyJWS(raw, set2)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrIdentityVerification, err)
		}
	}

	// Decode the JWT for issuer/audience/exp checks via jwx's parser
	// (without verification — we already verified the signature).
	tok, err := jwt.Parse(payload, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrIdentityVerification, err)
	}
	if iss := tok.Issuer(); iss != g.cfg.Issuer && iss != strings.TrimPrefix(g.cfg.Issuer, "https://") {
		return nil, fmt.Errorf("%w: bad iss: %s", ErrIdentityVerification, iss)
	}
	auds := tok.Audience()
	if !containsString(auds, g.cfg.ClientID) {
		return nil, fmt.Errorf("%w: bad aud", ErrIdentityVerification)
	}
	now := g.cfg.Now()
	if exp := tok.Expiration(); !exp.IsZero() && now.After(exp) {
		return nil, fmt.Errorf("%w: token expired", ErrIdentityVerification)
	}
	if iat := tok.IssuedAt(); !iat.IsZero() && iat.After(now.Add(2*time.Minute)) {
		return nil, fmt.Errorf("%w: iat in the future", ErrIdentityVerification)
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

// verifyJWS verifies the signature on a compact JWS using the
// provided JWK set (matching kid → key). Returns the decoded payload
// bytes on success.
func verifyJWS(raw string, set jwk.Set) ([]byte, error) {
	// Parse the message header to find the kid.
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("parse jws: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, errors.New("jws has no signatures")
	}
	hdr := sigs[0].ProtectedHeaders()
	kid := hdr.KeyID()
	alg := hdr.Algorithm()
	if alg == "" {
		return nil, errors.New("jws missing alg")
	}
	// Restrict to RSA SHA-256 (RS256) — what Google + Microsoft sign
	// with. Refusing other algs prevents alg-substitution attacks
	// (e.g. forging an HS256 token with the public key as the secret).
	if alg != jwa.RS256 {
		return nil, fmt.Errorf("unexpected jws alg: %s", alg)
	}
	var key jwk.Key
	if kid != "" {
		k, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("no jwk for kid=%q", kid)
		}
		key = k
	} else {
		// No kid — try the first key.
		if set.Len() == 0 {
			return nil, errors.New("jwks empty")
		}
		k, ok := set.Key(0)
		if !ok {
			return nil, errors.New("jwks first key missing")
		}
		key = k
	}
	verified, err := jws.Verify([]byte(raw), jws.WithKey(alg, key))
	if err != nil {
		return nil, fmt.Errorf("verify jws: %w", err)
	}
	return verified, nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
