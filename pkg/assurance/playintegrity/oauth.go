package playintegrity

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/elloloop/identity/pkg/assurance"
)

// jwtBearerGrant is the OAuth 2.0 JWT-bearer grant type (RFC 7523) Google
// token endpoints accept for service accounts.
// #nosec G101 -- a public RFC 7523 grant-type URN, not a credential.
const jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// assertionLifetime is the validity window claimed in the signed
// assertion; Google caps it at one hour.
const assertionLifetime = time.Hour

// refreshSkew renews a cached access token this long before its expiry
// so an in-flight call never presents a just-expired token.
const refreshSkew = time.Minute

// serviceAccountKey is the subset of a Google service-account JSON key
// file this package needs.
type serviceAccountKey struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// tokenSource exchanges a signed service-account assertion for an access
// token and caches it until near expiry. Safe for concurrent use.
type tokenSource struct {
	email    string
	key      *rsa.PrivateKey
	tokenURL string
	client   *http.Client
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// newTokenSource parses the service-account key file and prepares the
// bearer-assertion signer. tokenURLOverride replaces the key file's
// token_uri (tests point it at a fake endpoint).
func newTokenSource(saJSON []byte, tokenURLOverride string, client *http.Client, now func() time.Time) (*tokenSource, error) {
	if len(saJSON) == 0 {
		return nil, errors.New("playintegrity: service-account key is required")
	}
	var sa serviceAccountKey
	if err := json.Unmarshal(saJSON, &sa); err != nil {
		return nil, fmt.Errorf("playintegrity: parsing service-account key: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("playintegrity: service-account key missing client_email or private_key")
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("playintegrity: service-account private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("playintegrity: parsing service-account private key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("playintegrity: service-account key is %T, want RSA", parsed)
	}
	tokenURL := tokenURLOverride
	if tokenURL == "" {
		tokenURL = sa.TokenURI
	}
	if tokenURL == "" {
		return nil, errors.New("playintegrity: service-account key has no token_uri")
	}
	return &tokenSource{
		email:    sa.ClientEmail,
		key:      rsaKey,
		tokenURL: tokenURL,
		client:   client,
		now:      now,
	}, nil
}

// get returns a valid access token, exchanging a fresh assertion when the
// cached one is absent or near expiry.
func (ts *tokenSource) get(ctx context.Context) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.token != "" && ts.now().Add(refreshSkew).Before(ts.expires) {
		return ts.token, nil
	}

	assertion, err := ts.signAssertion()
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", jwtBearerGrant)
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: playintegrity: building token request: %w", assurance.ErrProviderUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: playintegrity: token endpoint: %w", assurance.ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("%w: playintegrity: reading token response: %w", assurance.ErrProviderUnavailable, err)
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("%w: playintegrity: token endpoint HTTP %d: %s", assurance.ErrProviderUnavailable, resp.StatusCode, truncateForLog(raw))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	// A non-positive expires_in would make every cached token look already
	// expired, so each call would re-run the exchange forever.
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" || out.ExpiresIn <= 0 {
		return "", fmt.Errorf("%w: playintegrity: malformed token response", assurance.ErrProviderUnavailable)
	}

	ts.token = out.AccessToken
	ts.expires = ts.now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return ts.token, nil
}

// signAssertion builds and RS256-signs the service-account JWT for the
// bearer grant. Its failures are OUR misconfiguration, not bad client
// evidence, so they carry ErrProviderUnavailable — otherwise a broken
// Android config would surface to operators as a wave of rejected
// attestations pointing at hostile clients.
func (ts *tokenSource) signAssertion() (string, error) {
	now := ts.now()
	claims := map[string]any{
		"iss":   ts.email,
		"scope": scope,
		"aud":   ts.tokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(assertionLifetime).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("%w: playintegrity: encoding assertion claims: %w", assurance.ErrProviderUnavailable, err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256, ts.key))
	if err != nil {
		return "", fmt.Errorf("%w: playintegrity: signing assertion: %w", assurance.ErrProviderUnavailable, err)
	}
	return string(signed), nil
}
