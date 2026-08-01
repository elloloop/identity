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
	// inflight is non-nil while one caller is performing the exchange; it
	// is closed when that attempt finishes (success or failure). Other
	// callers wait on it INSTEAD of queueing on mu, so the exchange never
	// runs under the lock — see get.
	inflight chan struct{}
	// lastErr / retryAt negative-cache a failed exchange. Without them a
	// failure teaches the next caller nothing: each one in turn becomes the
	// leader and pays the full client timeout, so during a Google outage N
	// concurrent verifications still cost ~N × timeout even though the
	// exchange is single-flighted. Holding the error briefly collapses that
	// to one attempt per window.
	lastErr error
	retryAt time.Time
}

// failureCacheTTL is how long a failed token exchange is remembered. Short
// enough that a brief upstream blip self-heals within one assurance-token
// lifetime, long enough that a sustained outage costs one exchange per
// window rather than one per request.
const failureCacheTTL = 5 * time.Second

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
//
// The exchange runs OUTSIDE the mutex, single-flighted through ts.inflight.
// Holding the lock across the HTTP call collapsed concurrent verifications
// into a queue: on the happy path that is a desirable single-flight, but on
// failure nothing is cached, so every queued waiter went on to run its own
// full attempt and the Nth waiter paid ~N × the client timeout during a
// Google token-endpoint outage. sync.Mutex.Lock is also not
// context-aware, so a caller whose request had already been cancelled still
// held its place in that queue. Waiters now block on a channel they can
// abandon when their own context ends, and a failed exchange releases all
// of them at once rather than serialising them.
func (ts *tokenSource) get(ctx context.Context) (string, error) {
	for {
		ts.mu.Lock()
		now := ts.now()
		if ts.token != "" && now.Add(refreshSkew).Before(ts.expires) {
			tok := ts.token
			ts.mu.Unlock()
			return tok, nil
		}
		if ts.lastErr != nil && now.Before(ts.retryAt) {
			err := ts.lastErr
			ts.mu.Unlock()
			return "", err
		}
		if wait := ts.inflight; wait != nil {
			ts.mu.Unlock()
			select {
			case <-wait:
				// The leader finished; loop to read whatever it published.
				// If it failed, this caller becomes the next leader rather
				// than inheriting a stale error.
				continue
			case <-ctx.Done():
				return "", fmt.Errorf("%w: playintegrity: token exchange: %w", assurance.ErrProviderUnavailable, ctx.Err())
			}
		}
		// This caller is the leader.
		done := make(chan struct{})
		ts.inflight = done
		ts.mu.Unlock()

		tok, err := ts.exchange(ctx)

		ts.mu.Lock()
		ts.inflight = nil
		if err == nil {
			ts.token = tok.token
			ts.expires = tok.expires
			ts.lastErr = nil
		} else {
			ts.lastErr = err
			ts.retryAt = ts.now().Add(failureCacheTTL)
		}
		ts.mu.Unlock()
		close(done)
		return tok.token, err
	}
}

// exchangedToken is the result of one successful assertion exchange.
type exchangedToken struct {
	token   string
	expires time.Time
}

// exchange performs one service-account assertion exchange. It touches no
// shared state, so it is safe to run without the lock held.
func (ts *tokenSource) exchange(ctx context.Context) (exchangedToken, error) {
	assertion, err := ts.signAssertion()
	if err != nil {
		return exchangedToken{}, err
	}
	form := url.Values{}
	form.Set("grant_type", jwtBearerGrant)
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return exchangedToken{}, fmt.Errorf("%w: playintegrity: building token request: %w", assurance.ErrProviderUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.client.Do(req)
	if err != nil {
		return exchangedToken{}, fmt.Errorf("%w: playintegrity: token endpoint: %w", assurance.ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return exchangedToken{}, fmt.Errorf("%w: playintegrity: reading token response: %w", assurance.ErrProviderUnavailable, err)
	}
	if resp.StatusCode/100 != 2 {
		return exchangedToken{}, fmt.Errorf("%w: playintegrity: token endpoint HTTP %d: %s", assurance.ErrProviderUnavailable, resp.StatusCode, truncateForLog(raw))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	// A non-positive expires_in would make every cached token look already
	// expired, so each call would re-run the exchange forever.
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" || out.ExpiresIn <= 0 {
		return exchangedToken{}, fmt.Errorf("%w: playintegrity: malformed token response", assurance.ErrProviderUnavailable)
	}

	return exchangedToken{
		token:   out.AccessToken,
		expires: ts.now().Add(time.Duration(out.ExpiresIn) * time.Second),
	}, nil
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
