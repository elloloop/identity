package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// jwksCache is a tiny in-process cache for a single JWKS URL with a
// fixed TTL. It is used by the Google and Microsoft Exchangers; we
// avoid jwx's auto-refreshing jwk.Cache so we don't hold a background
// goroutine for the lifetime of the process and so tests can assert
// fetch-call counts deterministically.
type jwksCache struct {
	mu       sync.Mutex
	url      string
	ttl      time.Duration
	client   *http.Client
	now      func() time.Time
	set      jwk.Set
	fetchedAt time.Time
}

func newJWKSCache(url string, ttl time.Duration, client *http.Client) *jwksCache {
	if client == nil {
		client = defaultHTTPClient()
	}
	return &jwksCache{
		url:    url,
		ttl:    ttl,
		client: client,
		now:    time.Now,
	}
}

// Get returns the cached jwk.Set, fetching from the upstream URL if
// no entry exists or the entry is older than ttl.
func (c *jwksCache) Get(ctx context.Context) (jwk.Set, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.set != nil && c.now().Sub(c.fetchedAt) < c.ttl {
		return c.set, nil
	}
	set, err := c.fetch(ctx)
	if err != nil {
		// On failure, return any stale cached set so a transient
		// JWKS endpoint outage doesn't take logins down. If we have
		// nothing cached, surface the error.
		if c.set != nil {
			return c.set, nil
		}
		return nil, err
	}
	c.set = set
	c.fetchedAt = c.now()
	return c.set, nil
}

// Invalidate clears the cached set so the next Get re-fetches. Used
// when ID-token verification fails on a key-not-found error: a key
// rotation may have happened since we last fetched.
func (c *jwksCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.set = nil
	c.fetchedAt = time.Time{}
}

func (c *jwksCache) fetch(ctx context.Context) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain body to allow connection reuse.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("jwks fetch: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("jwks read: %w", err)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("jwks parse: %w", err)
	}
	return set, nil
}
