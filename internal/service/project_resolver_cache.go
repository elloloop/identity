package service

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// resolutionKind distinguishes the two resolution namespaces so a
// credential public id can never collide with a hostname that happens to
// share its string value.
type resolutionKind uint8

const (
	resolveByCredentialKind resolutionKind = iota
	resolveByHostnameKind
)

type resolutionKey struct {
	kind resolutionKind
	id   string
}

// cachedResolution is a single memoized resolution. A clean miss is
// represented by a nil project with found=false; both hits and misses are
// cached so a hostile flood of unknown keys cannot bypass the cache and
// hammer the store. errors are never cached — a transient store failure
// must be retried, not pinned for a TTL.
type cachedResolution struct {
	project  *ResolvedProject
	expireAt time.Time
}

// CachingProjectResolver decorates a ProjectResolver with a short-TTL,
// LRU-bounded in-process cache. Project resolution runs on every request
// ahead of the rate limiter (and on every CORS preflight), so without a
// cache each request issues 2-3 uncached control-plane queries — a DoS
// amplification and scaling liability. The cache removes that cost while
// keeping correctness identical within the TTL window: a suspended project
// or revoked credential is re-read from the store once the (short) TTL
// elapses. Resolution semantics are otherwise unchanged — this is purely a
// performance/availability decorator.
type CachingProjectResolver struct {
	inner      ProjectResolver
	ttl        time.Duration
	maxEntries int
	now        func() time.Time

	mu      sync.Mutex
	entries map[resolutionKey]*list.Element // key → *list element holding lruEntry
	lru     *list.List                      // front = most recently used
}

type lruEntry struct {
	key resolutionKey
	val cachedResolution
}

var _ ProjectResolver = (*CachingProjectResolver)(nil)

// NewCachingProjectResolver wraps inner with a cache of the given TTL and
// max-entries bound. When inner is nil it returns nil (no control plane, so
// nothing to cache). When ttl <= 0 the cache is disabled and inner is
// returned unwrapped so the decorator adds no overhead. maxEntries <= 0
// falls back to defaultProjectResolutionCacheMaxEntries so a misconfigured
// bound can never make the cache unbounded.
func NewCachingProjectResolver(inner ProjectResolver, ttl time.Duration, maxEntries int) ProjectResolver {
	if inner == nil {
		return nil
	}
	if ttl <= 0 {
		return inner
	}
	if maxEntries <= 0 {
		maxEntries = defaultProjectResolutionCacheMaxEntries
	}
	return &CachingProjectResolver{
		inner:      inner,
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
		entries:    make(map[resolutionKey]*list.Element),
		lru:        list.New(),
	}
}

// defaultProjectResolutionCacheMaxEntries bounds the cache when the
// configured bound is non-positive. It is a backstop only; the real bound
// comes from config (GATEWAY_PROJECT_RESOLUTION_CACHE_MAX_ENTRIES).
const defaultProjectResolutionCacheMaxEntries = 10000

func (c *CachingProjectResolver) ResolveByCredential(ctx context.Context, publicID string) (*ResolvedProject, error) {
	return c.resolve(ctx, resolutionKey{resolveByCredentialKind, publicID}, c.inner.ResolveByCredential, publicID)
}

func (c *CachingProjectResolver) ResolveByHostname(ctx context.Context, hostname string) (*ResolvedProject, error) {
	return c.resolve(ctx, resolutionKey{resolveByHostnameKind, hostname}, c.inner.ResolveByHostname, hostname)
}

// resolve serves key from the cache when a non-expired entry exists,
// otherwise calls fetch, caches the (non-error) result, and returns it.
func (c *CachingProjectResolver) resolve(
	ctx context.Context,
	key resolutionKey,
	fetch func(context.Context, string) (*ResolvedProject, error),
	id string,
) (*ResolvedProject, error) {
	now := c.now()
	if hit, ok := c.load(key, now); ok {
		return hit.project, nil
	}

	project, err := fetch(ctx, id)
	if err != nil {
		return nil, err
	}
	c.store(key, cachedResolution{project: project, expireAt: now.Add(c.ttl)})
	return project, nil
}

// load returns the cached resolution for key when present and unexpired,
// promoting it to most-recently-used. An expired entry is dropped.
func (c *CachingProjectResolver) load(key resolutionKey, now time.Time) (cachedResolution, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return cachedResolution{}, false
	}
	ent := el.Value.(*lruEntry)
	if !ent.val.expireAt.After(now) {
		c.removeElement(el)
		return cachedResolution{}, false
	}
	c.lru.MoveToFront(el)
	return ent.val, true
}

// store inserts or refreshes key, evicting the least-recently-used entry
// when the bound is exceeded.
func (c *CachingProjectResolver) store(key resolutionKey, val cachedResolution) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		el.Value.(*lruEntry).val = val
		c.lru.MoveToFront(el)
		return
	}
	el := c.lru.PushFront(&lruEntry{key: key, val: val})
	c.entries[key] = el
	if c.lru.Len() > c.maxEntries {
		c.removeElement(c.lru.Back())
	}
}

// removeElement drops el from both the list and the index. The caller holds
// c.mu.
func (c *CachingProjectResolver) removeElement(el *list.Element) {
	if el == nil {
		return
	}
	c.lru.Remove(el)
	delete(c.entries, el.Value.(*lruEntry).key)
}
