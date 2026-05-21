package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/elloloop/identity/internal/service"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// sessionMetricName is the histogram identifier deployers wire into
// their dashboards / alerts.
const sessionMetricName = "identity_session_lookup_duration_seconds"

// SessionMetrics owns the Prometheus handles exposed when the service
// is running in `mode=session`. The histogram measures end-to-end
// session lookup latency on the auth hot path — cache hits land in
// the sub-microsecond bucket; cache misses include the repository
// round-trip.
type SessionMetrics struct {
	lookupDuration *prometheus.HistogramVec
}

// NewSessionMetrics registers the metric handles with reg. Pass nil
// to register against a fresh isolated registry (suitable for tests).
// The production binary passes prometheus.DefaultRegisterer so
// /metrics serves the counters.
func NewSessionMetrics(reg prometheus.Registerer) (*SessionMetrics, error) {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	hist := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: sessionMetricName,
		Help: "Session lookup duration in seconds (mode=session), labelled by outcome (hit/miss/revoked/missing).",
		// Custom buckets: warm-cache reads land in sub-microsecond
		// territory, repo round-trips at single-digit milliseconds.
		Buckets: []float64{
			0.0000005, // 500ns
			0.000001,  // 1µs
			0.000005,  // 5µs
			0.00001,   // 10µs
			0.0001,    // 100µs
			0.001,     // 1ms
			0.005,     // 5ms
			0.01,      // 10ms
			0.05,      // 50ms
			0.1,       // 100ms
		},
	}, []string{"outcome"})
	if err := reg.Register(hist); err != nil {
		return nil, err
	}
	return &SessionMetrics{lookupDuration: hist}, nil
}

// SessionLookup is the interface the verification middleware uses to
// resolve a `sid` claim to an active session. It's narrower than
// service.Repository so tests can swap in a fake and the middleware
// only takes a dependency on what it actually needs.
type SessionLookup interface {
	GetSessionBySid(ctx context.Context, sid string) (*service.SessionRecord, error)
}

// SessionCache wraps a SessionLookup with an in-process TTL cache. The
// cache is keyed by SID; entries store the resolved active/revoked
// state plus the deadline past which the entry must be re-read.
//
// The cache is invalidated synchronously on RevokeSession / RevokeSessionsForUser
// inside the same process. Cross-replica revocation is bounded by the
// TTL — a session revoked on replica A is invisible to replica B's
// cached entry for at most TTL seconds.
//
// TTL = 0 means strict mode: every authenticated request reads the
// repository.
//
// Implementation: a plain sync.Map of sid → cacheEntry. We deliberately
// avoid ristretto here — the cardinality is bounded by active
// sessions, eviction is by TTL (not size), and the workload is
// read-heavy with occasional invalidation. ristretto's strengths
// (admission policy, cost-based eviction) don't apply.
type SessionCache struct {
	source  SessionLookup
	ttl     time.Duration
	metrics *SessionMetrics
	now     func() time.Time

	entries sync.Map // sid (string) → *cacheEntry
}

type cacheEntry struct {
	mu       sync.Mutex
	rec      *service.SessionRecord
	deadline time.Time
	missing  bool // true means "verified missing at deadline time"
}

// NewSessionCache constructs a cache. When ttl <= 0 the cache is in
// strict mode and every lookup goes through to source.
func NewSessionCache(source SessionLookup, ttl time.Duration, metrics *SessionMetrics) *SessionCache {
	if source == nil {
		return nil
	}
	return &SessionCache{
		source:  source,
		ttl:     ttl,
		metrics: metrics,
		now:     time.Now,
	}
}

// SessionState is the result of a session lookup. The middleware
// rejects requests whose state is anything other than Active.
type SessionState int

const (
	// SessionStateActive: row exists and revoked_at_ms == 0.
	SessionStateActive SessionState = iota
	// SessionStateRevoked: row exists with revoked_at_ms != 0.
	SessionStateRevoked
	// SessionStateMissing: no row for this sid. Always rejected — an
	// access token carrying a sid the service has never minted (or
	// has GC'd) must be treated as forged or expired-server-side.
	SessionStateMissing
)

// Lookup resolves the session state for sid. TTL=0 always reads the
// repository; otherwise a cached entry whose deadline hasn't passed
// is served without I/O. Cache misses populate the entry under a
// per-entry lock so concurrent first-readers issue a single repo
// round-trip.
func (c *SessionCache) Lookup(ctx context.Context, sid string) (SessionState, error) {
	if c == nil {
		return SessionStateActive, nil
	}
	start := c.now()
	if c.ttl <= 0 {
		state, err := c.read(ctx, sid)
		c.observe(start, state, err)
		return state, err
	}
	now := start

	// Fast path: cache hit served lock-free per sid. The entry's mu
	// protects the deadline + payload pair; sync.Map handles the
	// per-key concurrency for the outer map.
	if raw, ok := c.entries.Load(sid); ok {
		entry := raw.(*cacheEntry)
		entry.mu.Lock()
		if entry.deadline.After(now) {
			state := stateFromEntry(entry)
			entry.mu.Unlock()
			c.observeHit(start, state)
			return state, nil
		}
		entry.mu.Unlock()
	}

	// Slow path: take/create the per-sid entry lock and refill it.
	raw, _ := c.entries.LoadOrStore(sid, &cacheEntry{})
	entry := raw.(*cacheEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	// A concurrent refiller may have already won; re-check the deadline
	// before issuing the repo call.
	if entry.deadline.After(c.now()) {
		state := stateFromEntry(entry)
		c.observeHit(start, state)
		return state, nil
	}

	state, err := c.read(ctx, sid)
	if err != nil {
		// Don't cache transient errors — the next request retries the
		// repo. Cache poisoning would block legitimate users until TTL.
		c.observe(start, state, err)
		return state, err
	}
	// Cache only the minimal state required to answer subsequent reads.
	// The full SessionRecord isn't kept — the hot path never inspects
	// anything other than SID + RevokedAtMs presence.
	switch state {
	case SessionStateActive:
		entry.rec = &service.SessionRecord{SID: sid}
		entry.missing = false
	case SessionStateRevoked:
		entry.rec = &service.SessionRecord{SID: sid, RevokedAtMs: 1}
		entry.missing = false
	case SessionStateMissing:
		entry.rec = nil
		entry.missing = true
	}
	entry.deadline = c.now().Add(c.ttl)
	c.observe(start, state, nil)
	return state, nil
}

func (c *SessionCache) read(ctx context.Context, sid string) (SessionState, error) {
	rec, err := c.source.GetSessionBySid(ctx, sid)
	if err != nil {
		return SessionStateMissing, err
	}
	if rec == nil {
		return SessionStateMissing, nil
	}
	if rec.RevokedAtMs != 0 {
		return SessionStateRevoked, nil
	}
	return SessionStateActive, nil
}

func stateFromEntry(e *cacheEntry) SessionState {
	if e.missing {
		return SessionStateMissing
	}
	if e.rec != nil && e.rec.RevokedAtMs != 0 {
		return SessionStateRevoked
	}
	return SessionStateActive
}

func (c *SessionCache) observe(start time.Time, state SessionState, err error) {
	if c.metrics == nil {
		return
	}
	outcome := outcomeLabel(state, err, false)
	c.metrics.lookupDuration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
}

func (c *SessionCache) observeHit(start time.Time, state SessionState) {
	if c.metrics == nil {
		return
	}
	outcome := outcomeLabel(state, nil, true)
	c.metrics.lookupDuration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
}

func outcomeLabel(state SessionState, err error, hit bool) string {
	if err != nil {
		return "error"
	}
	switch state {
	case SessionStateActive:
		if hit {
			return "hit"
		}
		return "miss"
	case SessionStateRevoked:
		if hit {
			return "hit_revoked"
		}
		return "miss_revoked"
	}
	// SessionStateMissing — only ever the result of a fresh repo read,
	// since a confirmed-missing entry isn't worth distinguishing as a
	// "hit" for alerting purposes.
	return "missing"
}

// Invalidate drops cached state for sid. Called from
// RevokingSessionLookup wrappers so a same-process revoke is visible
// on the very next request.
func (c *SessionCache) Invalidate(sid string) {
	if c == nil {
		return
	}
	c.entries.Delete(sid)
}

// InvalidateAll clears every cached entry. Used by RevokeSessionsForUser
// because we don't index entries by user id — the access pattern
// (revoke-on-replay) is rare enough that an O(n) Range is cheaper
// than maintaining a second index on the hot path.
func (c *SessionCache) InvalidateAll() {
	if c == nil {
		return
	}
	c.entries.Range(func(k, _ any) bool {
		c.entries.Delete(k)
		return true
	})
}

// RevokingSessionRepository wraps a service.Repository so that every
// RevokeSession / RevokeSessionsForUser call also invalidates the
// in-process cache. Wiring sits in internal/app/app.go so the wrap
// only happens in `mode=session`.
type RevokingSessionRepository struct {
	service.Repository
	cache *SessionCache
}

// WrapSessionRepository returns a Repository that invalidates the
// cache synchronously on session revocation. The wrapped Repository
// keeps all of its other behaviour intact.
func WrapSessionRepository(repo service.Repository, cache *SessionCache) service.Repository {
	if cache == nil {
		return repo
	}
	return &RevokingSessionRepository{Repository: repo, cache: cache}
}

// RevokeSession invalidates the cache before calling through. Order
// matters: invalidating after a failed RevokeSession would leak a
// stale "active" cache entry; invalidating before a successful one
// means the worst case is a single extra cache miss.
func (r *RevokingSessionRepository) RevokeSession(ctx context.Context, sid string, atMs int64) error {
	r.cache.Invalidate(sid)
	return r.Repository.RevokeSession(ctx, sid, atMs)
}

// RevokeSessionsForUser drops every cached entry. We don't index by
// user id (see InvalidateAll comment) and a deployer-side revoke
// happens at human latency, so the O(n) sweep is the right trade.
func (r *RevokingSessionRepository) RevokeSessionsForUser(ctx context.Context, userID string, atMs int64) error {
	r.cache.InvalidateAll()
	return r.Repository.RevokeSessionsForUser(ctx, userID, atMs)
}

// SessionAuthMiddleware verifies JWT Bearer tokens AND consults the
// session cache when the token carries a `sid` claim. This is the
// drop-in replacement for AuthMiddleware when mode=session is on.
//
// When the cache is nil (mode=ttl) the behaviour is identical to
// AuthMiddleware. When the cache is non-nil:
//
//   - Tokens without a sid claim are still accepted, so an upgrade
//     deployment that ships verifiers ahead of issuers does not lock
//     out in-flight tokens. The hot path stays the same for these.
//   - Tokens with a sid claim are rejected when the cached/refreshed
//     state is anything other than Active.
func SessionAuthMiddleware(kp jwtpkg.KeyProvider, expectedTenant, expectedAudience string, requireAudience bool, cache *SessionCache) func(http.Handler) http.Handler {
	if cache == nil {
		// mode=ttl path: identical to AuthMiddleware. Returning the
		// same function avoids a wrapper layer on the zero-cost path.
		return AuthMiddleware(kp, expectedTenant, expectedAudience, requireAudience)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			// Strip any client-supplied identity headers so a caller can
			// never spoof the values the middleware injects downstream.
			clearAuthHeaders(r)
			if isAuthExempt(path) {
				// Even on exempt paths we parse a present token so the
				// downstream handler can read X-Authenticated-User-Id.
				// When the token carries a sid claim AND we're in
				// mode=session, the session lookup applies — otherwise
				// a revoked session would still get the "I'm signed in"
				// view on endpoints like GetCurrentUser.
				if token := extractBearerToken(r); token != "" {
					if claims, err := jwtpkg.VerifyAccessToken(token, kp, expectedTenant, expectedAudience, requireAudience); err == nil {
						if claims.SID != "" {
							state, lookupErr := cache.Lookup(r.Context(), claims.SID)
							if lookupErr == nil && state == SessionStateActive {
								setAuthHeaders(r, claims)
							}
							// On lookup error / revoked / missing: do
							// NOT set the user-id header; the handler
							// then treats the request as unauthenticated
							// without the middleware needing to reject
							// (preserves the existing exempt-path contract
							// for unauthenticated callers).
						} else {
							setAuthHeaders(r, claims)
						}
					}
				}
				next.ServeHTTP(w, r)
				return
			}
			token := extractBearerToken(r)
			if token == "" {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"code":"unauthenticated","message":"Missing Authorization header"}`, http.StatusUnauthorized)
				return
			}
			claims, err := jwtpkg.VerifyAccessToken(token, kp, expectedTenant, expectedAudience, requireAudience)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"code":"unauthenticated","message":"Invalid or expired access token"}`, http.StatusUnauthorized)
				return
			}
			if claims.SID != "" {
				state, lookupErr := cache.Lookup(r.Context(), claims.SID)
				if lookupErr != nil {
					w.Header().Set("Content-Type", "application/json")
					http.Error(w, `{"code":"unavailable","message":"Session lookup failed"}`, http.StatusServiceUnavailable)
					return
				}
				if state != SessionStateActive {
					w.Header().Set("Content-Type", "application/json")
					http.Error(w, `{"code":"unauthenticated","message":"Session revoked"}`, http.StatusUnauthorized)
					return
				}
			}
			setAuthHeaders(r, claims)
			next.ServeHTTP(w, r)
		})
	}
}
