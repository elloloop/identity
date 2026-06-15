package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

// countingResolver is a fake ProjectResolver that records how many times
// each method is called and returns canned results keyed by input.
type countingResolver struct {
	mu          sync.Mutex
	byCred      map[string]*ResolvedProject
	byHost      map[string]*ResolvedProject
	credCalls   int
	hostCalls   int
	credErr     error
	hostErr     error
	lastCredArg string
}

func newCountingResolver() *countingResolver {
	return &countingResolver{
		byCred: map[string]*ResolvedProject{},
		byHost: map[string]*ResolvedProject{},
	}
}

func (c *countingResolver) ResolveByCredential(_ context.Context, publicID string) (*ResolvedProject, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.credCalls++
	c.lastCredArg = publicID
	if c.credErr != nil {
		return nil, c.credErr
	}
	return c.byCred[publicID], nil
}

func (c *countingResolver) ResolveByHostname(_ context.Context, hostname string) (*ResolvedProject, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hostCalls++
	if c.hostErr != nil {
		return nil, c.hostErr
	}
	return c.byHost[hostname], nil
}

func newTestCache(inner ProjectResolver, ttl time.Duration, max int, now func() time.Time) *CachingProjectResolver {
	c := NewCachingProjectResolver(inner, ttl, max).(*CachingProjectResolver)
	c.now = now
	return c
}

func TestCachingResolver_NilInnerReturnsNil(t *testing.T) {
	if got := NewCachingProjectResolver(nil, time.Second, 10); got != nil {
		t.Fatalf("nil inner: want nil decorator, got %T", got)
	}
}

func TestCachingResolver_ZeroTTLReturnsInnerUnwrapped(t *testing.T) {
	inner := newCountingResolver()
	if got := NewCachingProjectResolver(inner, 0, 10); got != ProjectResolver(inner) {
		t.Fatalf("ttl<=0: want inner unwrapped, got %T", got)
	}
}

func TestCachingResolver_HitAvoidsSecondCall(t *testing.T) {
	inner := newCountingResolver()
	inner.byCred["pub_1"] = &ResolvedProject{ID: "proj_1", StorageScopeID: "scope_1"}
	clock := time.Unix(0, 0)
	c := newTestCache(inner, 30*time.Second, 10, func() time.Time { return clock })

	for i := 0; i < 5; i++ {
		rp, err := c.ResolveByCredential(context.Background(), "pub_1")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if rp == nil || rp.ID != "proj_1" {
			t.Fatalf("call %d: got %+v", i, rp)
		}
	}
	if inner.credCalls != 1 {
		t.Fatalf("want 1 inner call, got %d", inner.credCalls)
	}
}

func TestCachingResolver_CachesMisses(t *testing.T) {
	inner := newCountingResolver() // pub_unknown not present → miss
	clock := time.Unix(0, 0)
	c := newTestCache(inner, 30*time.Second, 10, func() time.Time { return clock })

	for i := 0; i < 3; i++ {
		rp, err := c.ResolveByCredential(context.Background(), "pub_unknown")
		if err != nil {
			t.Fatal(err)
		}
		if rp != nil {
			t.Fatalf("want miss, got %+v", rp)
		}
	}
	if inner.credCalls != 1 {
		t.Fatalf("misses must be cached: want 1 inner call, got %d", inner.credCalls)
	}
}

func TestCachingResolver_ExpiresAfterTTL(t *testing.T) {
	inner := newCountingResolver()
	inner.byHost["app.example.com"] = &ResolvedProject{ID: "proj_h"}
	clock := time.Unix(0, 0)
	c := newTestCache(inner, 30*time.Second, 10, func() time.Time { return clock })

	if _, err := c.ResolveByHostname(context.Background(), "app.example.com"); err != nil {
		t.Fatal(err)
	}
	// Within TTL: served from cache.
	clock = clock.Add(29 * time.Second)
	if _, err := c.ResolveByHostname(context.Background(), "app.example.com"); err != nil {
		t.Fatal(err)
	}
	if inner.hostCalls != 1 {
		t.Fatalf("within TTL: want 1 inner call, got %d", inner.hostCalls)
	}
	// Past TTL: re-read from store.
	clock = clock.Add(2 * time.Second) // now t=31s > 30s deadline
	if _, err := c.ResolveByHostname(context.Background(), "app.example.com"); err != nil {
		t.Fatal(err)
	}
	if inner.hostCalls != 2 {
		t.Fatalf("past TTL: want 2 inner calls, got %d", inner.hostCalls)
	}
}

// A credential revoked (now a miss) at the store re-resolves correctly once
// the TTL elapses — it is never served stale beyond the TTL.
func TestCachingResolver_RevokedReResolvesAfterTTL(t *testing.T) {
	inner := newCountingResolver()
	inner.byCred["pub_live"] = &ResolvedProject{ID: "proj_live"}
	clock := time.Unix(0, 0)
	c := newTestCache(inner, 30*time.Second, 10, func() time.Time { return clock })

	rp, _ := c.ResolveByCredential(context.Background(), "pub_live")
	if rp == nil || rp.ID != "proj_live" {
		t.Fatalf("initial resolve: got %+v", rp)
	}

	// Credential revoked / project suspended at the store → now a miss.
	inner.mu.Lock()
	delete(inner.byCred, "pub_live")
	inner.mu.Unlock()

	// Still within TTL: stale hit is acceptable.
	rp, _ = c.ResolveByCredential(context.Background(), "pub_live")
	if rp == nil {
		t.Fatalf("within TTL: expected stale hit")
	}

	// Past TTL: must reflect revocation (miss).
	clock = clock.Add(31 * time.Second)
	rp, _ = c.ResolveByCredential(context.Background(), "pub_live")
	if rp != nil {
		t.Fatalf("past TTL: revoked credential must be a miss, got %+v", rp)
	}
}

func TestCachingResolver_DoesNotCacheErrors(t *testing.T) {
	inner := newCountingResolver()
	inner.credErr = errors.New("boom")
	clock := time.Unix(0, 0)
	c := newTestCache(inner, 30*time.Second, 10, func() time.Time { return clock })

	for i := 0; i < 3; i++ {
		if _, err := c.ResolveByCredential(context.Background(), "pub_x"); err == nil {
			t.Fatalf("call %d: want error", i)
		}
	}
	if inner.credCalls != 3 {
		t.Fatalf("errors must not be cached: want 3 inner calls, got %d", inner.credCalls)
	}
}

// Credential and hostname namespaces never collide even on identical keys.
func TestCachingResolver_NamespacesDoNotCollide(t *testing.T) {
	inner := newCountingResolver()
	inner.byCred["same"] = &ResolvedProject{ID: "from_cred"}
	inner.byHost["same"] = &ResolvedProject{ID: "from_host"}
	clock := time.Unix(0, 0)
	c := newTestCache(inner, 30*time.Second, 10, func() time.Time { return clock })

	cred, _ := c.ResolveByCredential(context.Background(), "same")
	host, _ := c.ResolveByHostname(context.Background(), "same")
	if cred.ID != "from_cred" || host.ID != "from_host" {
		t.Fatalf("namespace collision: cred=%+v host=%+v", cred, host)
	}
}

// The LRU bound evicts the least-recently-used entry; an evicted key
// re-reads the store on its next lookup.
func TestCachingResolver_LRUEviction(t *testing.T) {
	inner := newCountingResolver()
	for i := 0; i < 4; i++ {
		inner.byCred[strconv.Itoa(i)] = &ResolvedProject{ID: fmt.Sprintf("p%d", i)}
	}
	clock := time.Unix(0, 0)
	c := newTestCache(inner, time.Hour, 2, func() time.Time { return clock })

	ctx := context.Background()
	c.ResolveByCredential(ctx, "0") // cache: [0]
	c.ResolveByCredential(ctx, "1") // cache: [1,0]
	c.ResolveByCredential(ctx, "0") // touch 0 -> cache: [0,1]
	c.ResolveByCredential(ctx, "2") // inserts 2, evicts LRU=1 -> cache: [2,0]

	// 0,1,2 each hit the store once; the repeat lookup of 0 was a cache hit.
	if inner.credCalls != 3 {
		t.Fatalf("want 3 inner calls so far, got %d", inner.credCalls)
	}
	// 0 still cached (no new call); 1 was evicted (new call).
	c.ResolveByCredential(ctx, "0")
	if inner.credCalls != 3 {
		t.Fatalf("0 should be cached, got %d calls", inner.credCalls)
	}
	c.ResolveByCredential(ctx, "1")
	if inner.credCalls != 4 {
		t.Fatalf("1 should have been evicted, got %d calls", inner.credCalls)
	}
}
