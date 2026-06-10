package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
)

// stubLookup is a SessionLookup the cache uses to drive its slow path.
// reads counts every GetSessionBySid call so tests can assert the
// cache turned N requests into 1 repo read.
type stubLookup struct {
	mu    sync.Mutex
	rows  map[string]*service.SessionRecord
	reads atomic.Int64
	err   error
}

func newStubLookup() *stubLookup {
	return &stubLookup{rows: map[string]*service.SessionRecord{}}
}

func (s *stubLookup) GetSessionBySid(_ context.Context, sid string) (*service.SessionRecord, error) {
	s.reads.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[sid]; ok {
		cp := *r
		return &cp, nil
	}
	return nil, nil
}

func (s *stubLookup) put(rec *service.SessionRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *rec
	s.rows[rec.SID] = &cp
}

func (s *stubLookup) revoke(sid string, atMs int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[sid]; ok {
		r.RevokedAtMs = atMs
	}
}

func TestSessionCache_TTL0_AlwaysReadsRepo(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "s1", UserID: "u1"})

	cache := NewSessionCache(src, 0, nil)

	for i := 0; i < 5; i++ {
		state, err := cache.Lookup(context.Background(), "s1")
		if err != nil || state != SessionStateActive {
			t.Fatalf("iter %d: state=%v err=%v", i, state, err)
		}
	}
	if got := src.reads.Load(); got != 5 {
		t.Fatalf("strict mode reads = %d, want 5", got)
	}
}

func TestSessionCache_WarmCache_OneReadPerEntry(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "s1", UserID: "u1"})

	cache := NewSessionCache(src, 60*time.Second, nil)

	for i := 0; i < 10; i++ {
		state, err := cache.Lookup(context.Background(), "s1")
		if err != nil || state != SessionStateActive {
			t.Fatalf("iter %d: state=%v err=%v", i, state, err)
		}
	}
	// First call populates, the next nine hit the cache.
	if got := src.reads.Load(); got != 1 {
		t.Fatalf("warm-cache reads = %d, want 1", got)
	}
}

func TestSessionCache_RespectsTTLDeadline(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "s1", UserID: "u1"})

	// 1ns TTL: every call refills.
	cache := NewSessionCache(src, time.Nanosecond, nil)
	for i := 0; i < 3; i++ {
		if _, err := cache.Lookup(context.Background(), "s1"); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		// Sleep past the TTL so the next read sees a stale deadline.
		time.Sleep(2 * time.Microsecond)
	}
	if got := src.reads.Load(); got < 3 {
		t.Fatalf("ttl-expiry reads = %d, want >= 3", got)
	}
}

func TestSessionCache_InvalidateClearsEntry(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "s1", UserID: "u1"})

	cache := NewSessionCache(src, 60*time.Second, nil)
	if _, err := cache.Lookup(context.Background(), "s1"); err != nil {
		t.Fatalf("warm: %v", err)
	}
	cache.Invalidate("s1")
	src.revoke("s1", 100)

	state, err := cache.Lookup(context.Background(), "s1")
	if err != nil {
		t.Fatalf("post-invalidate: %v", err)
	}
	if state != SessionStateRevoked {
		t.Fatalf("post-invalidate state = %v, want Revoked", state)
	}
	if got := src.reads.Load(); got != 2 {
		t.Fatalf("reads after invalidate = %d, want 2", got)
	}
}

func TestSessionCache_RevokedSessionRejected(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "s1", UserID: "u1", RevokedAtMs: 200})

	cache := NewSessionCache(src, 60*time.Second, nil)
	state, err := cache.Lookup(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if state != SessionStateRevoked {
		t.Fatalf("state = %v, want Revoked", state)
	}
}

func TestSessionCache_MissingSessionRejected(t *testing.T) {
	t.Parallel()
	src := newStubLookup()

	cache := NewSessionCache(src, 60*time.Second, nil)
	state, err := cache.Lookup(context.Background(), "no-such")
	if err != nil {
		t.Fatal(err)
	}
	if state != SessionStateMissing {
		t.Fatalf("state = %v, want Missing", state)
	}
}

func TestSessionCache_ErrorNotCached(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.err = errors.New("db down")

	cache := NewSessionCache(src, 60*time.Second, nil)
	if _, err := cache.Lookup(context.Background(), "s1"); err == nil {
		t.Fatal("want error, got nil")
	}
	// Recover: the next call must re-read rather than return cached error.
	src.mu.Lock()
	src.err = nil
	src.rows["s1"] = &service.SessionRecord{SID: "s1"}
	src.mu.Unlock()
	state, err := cache.Lookup(context.Background(), "s1")
	if err != nil {
		t.Fatalf("post-recovery: %v", err)
	}
	if state != SessionStateActive {
		t.Fatalf("post-recovery state = %v", state)
	}
}

func TestRevokingSessionRepository_InvalidatesCacheOnRevoke(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "s1", UserID: "u1"})

	cache := NewSessionCache(src, 60*time.Second, nil)
	wrap := WrapSessionRepository(&fakeRepo{stub: src}, cache)

	// Warm the cache.
	if _, err := cache.Lookup(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	// Revoke through the wrapper.
	if err := wrap.RevokeSession(context.Background(), "s1", 200); err != nil {
		t.Fatal(err)
	}
	// fakeRepo's RevokeSession mutates the underlying stub; the next
	// lookup must see Revoked because the cache entry was invalidated.
	state, err := cache.Lookup(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if state != SessionStateRevoked {
		t.Fatalf("state after revoke = %v, want Revoked", state)
	}
}

func TestSessionMetrics_RecordsLookupOutcome(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "s1", UserID: "u1"})

	reg := prometheus.NewRegistry()
	metrics, err := NewSessionMetrics(reg)
	if err != nil {
		t.Fatalf("NewSessionMetrics: %v", err)
	}
	cache := NewSessionCache(src, 60*time.Second, metrics)
	for i := 0; i < 3; i++ {
		if _, err := cache.Lookup(context.Background(), "s1"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mf := range got {
		if mf.GetName() == "identity_session_lookup_duration_seconds" {
			found = true
		}
	}
	if !found {
		t.Fatal("histogram identity_session_lookup_duration_seconds not registered")
	}
}

// fakeRepo embeds service.Repository to satisfy the wrap interface.
// It delegates RevokeSession to the stub lookup so the test can
// observe the in-memory state. Other methods panic — the test never
// uses them.
type fakeRepo struct {
	service.Repository
	stub *stubLookup
}

func (r *fakeRepo) RevokeSession(_ context.Context, sid string, atMs int64) error {
	r.stub.revoke(sid, atMs)
	return nil
}

func (r *fakeRepo) RevokeSessionsForUser(_ context.Context, userID string, atMs int64) error {
	r.stub.mu.Lock()
	defer r.stub.mu.Unlock()
	for _, row := range r.stub.rows {
		if row.UserID == userID && row.RevokedAtMs == 0 {
			row.RevokedAtMs = atMs
		}
	}
	return nil
}

// ── Middleware integration ────────────────────────────────────────────

func TestSessionAuthMiddleware_TTLMode_NoLookup(t *testing.T) {
	t.Parallel()
	keyRing, kid := newTestKeyRing(t)

	called := atomic.Bool{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	mw := SessionAuthMiddleware(keyRing, "tenant-1", "", false, nil)(next)
	token := mintTokenWithSID(t, keyRing, kid, "user-1", "tenant-1", "")
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/Echo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rw.Code)
	}
	if !called.Load() {
		t.Fatal("next not invoked")
	}
}

func TestSessionAuthMiddleware_RejectsRevokedSID(t *testing.T) {
	t.Parallel()
	keyRing, kid := newTestKeyRing(t)
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "sid-revoked", UserID: "u1", RevokedAtMs: 200})
	cache := NewSessionCache(src, 60*time.Second, nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next should not be invoked for a revoked session")
	})
	mw := SessionAuthMiddleware(keyRing, "tenant-1", "", false, cache)(next)

	token := mintTokenWithSID(t, keyRing, kid, "user-1", "tenant-1", "sid-revoked")
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/Echo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), "Session revoked") {
		t.Fatalf("body = %q, want 'Session revoked'", rw.Body.String())
	}
}

// TestSessionAuthMiddleware_InstanceSignup_ExemptNoToken_Passes is the
// mode=session counterpart of the AuthMiddleware bootstrap test: with a
// non-nil session cache the chain takes the session-aware branch, and the
// unauthenticated InstanceSignup bootstrap must still pass through rather
// than being 401-rejected.
func TestSessionAuthMiddleware_InstanceSignup_ExemptNoToken_Passes(t *testing.T) {
	t.Parallel()
	keyRing, _ := newTestKeyRing(t)
	cache := NewSessionCache(newStubLookup(), 60*time.Second, nil)

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	mw := SessionAuthMiddleware(keyRing, "tenant-1", "", false, cache)(next)

	// No Authorization header — the fresh-instance bootstrap case.
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/InstanceSignup", nil)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)

	if !called {
		t.Fatal("InstanceSignup must reach the handler without a token")
	}
	if rw.Code == http.StatusUnauthorized {
		t.Fatalf("InstanceSignup must not be 401-rejected; body = %q", rw.Body.String())
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rw.Code)
	}
}

func TestSessionAuthMiddleware_AcceptsActiveSID(t *testing.T) {
	t.Parallel()
	keyRing, kid := newTestKeyRing(t)
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "sid-ok", UserID: "u1"})
	cache := NewSessionCache(src, 60*time.Second, nil)

	called := atomic.Bool{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	mw := SessionAuthMiddleware(keyRing, "tenant-1", "", false, cache)(next)

	token := mintTokenWithSID(t, keyRing, kid, "user-1", "tenant-1", "sid-ok")
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/Echo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rw.Code)
	}
	if !called.Load() {
		t.Fatal("next not invoked")
	}
}

func TestSessionAuthMiddleware_TokenWithoutSIDPassesThroughInSessionMode(t *testing.T) {
	// Pre-mode-flip tokens (issued in mode=ttl) have no sid claim. A
	// deployer flipping the verifier on first must still accept those
	// in-flight tokens; otherwise every active user is locked out
	// at the moment of the config change.
	t.Parallel()
	keyRing, kid := newTestKeyRing(t)
	src := newStubLookup()
	cache := NewSessionCache(src, 60*time.Second, nil)

	called := atomic.Bool{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	mw := SessionAuthMiddleware(keyRing, "tenant-1", "", false, cache)(next)

	token := mintTokenWithSID(t, keyRing, kid, "user-1", "tenant-1", "") // no sid
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/Echo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rw.Code, rw.Body.String())
	}
	if !called.Load() {
		t.Fatal("next not invoked")
	}
	if src.reads.Load() != 0 {
		t.Fatalf("repo reads = %d, want 0 for token without sid", src.reads.Load())
	}
}

// ── Nil-safety / wrapper paths ────────────────────────────────────────

func TestSessionCache_NilSource_ReturnsNil(t *testing.T) {
	t.Parallel()
	if c := NewSessionCache(nil, time.Minute, nil); c != nil {
		t.Fatalf("NewSessionCache(nil) = %v, want nil", c)
	}
}

func TestSessionMetrics_NilRegistererUsesIsolatedRegistry(t *testing.T) {
	t.Parallel()
	m, err := NewSessionMetrics(nil)
	if err != nil {
		t.Fatalf("NewSessionMetrics(nil): %v", err)
	}
	if m == nil {
		t.Fatal("NewSessionMetrics(nil) returned nil metrics")
	}
}

func TestSessionMetrics_DuplicateRegistrationErrors(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	if _, err := NewSessionMetrics(reg); err != nil {
		t.Fatalf("first NewSessionMetrics: %v", err)
	}
	if _, err := NewSessionMetrics(reg); err == nil {
		t.Fatal("second NewSessionMetrics: want collision error, got nil")
	}
}

func TestSessionCache_NilReceiverIsSafe(t *testing.T) {
	t.Parallel()
	var c *SessionCache
	// Lookup on a nil cache is the "session lookup disabled" path —
	// every sid is treated as Active so mode=ttl wiring stays
	// no-op-friendly.
	state, err := c.Lookup(context.Background(), "any")
	if err != nil || state != SessionStateActive {
		t.Fatalf("nil-receiver Lookup: state=%v err=%v", state, err)
	}
	c.Invalidate("any") // must not panic
	c.InvalidateAll()
}

func TestSessionCache_InvalidateAllDropsEveryEntry(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "s1", UserID: "u1"})
	src.put(&service.SessionRecord{SID: "s2", UserID: "u1"})
	cache := NewSessionCache(src, time.Minute, nil)
	// Populate both entries.
	if _, err := cache.Lookup(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Lookup(context.Background(), "s2"); err != nil {
		t.Fatal(err)
	}
	cache.InvalidateAll()
	src.revoke("s1", 100)
	src.revoke("s2", 100)
	// Both must re-read the source and observe Revoked.
	state, _ := cache.Lookup(context.Background(), "s1")
	if state != SessionStateRevoked {
		t.Fatalf("s1 after InvalidateAll: state=%v, want Revoked", state)
	}
	state, _ = cache.Lookup(context.Background(), "s2")
	if state != SessionStateRevoked {
		t.Fatalf("s2 after InvalidateAll: state=%v, want Revoked", state)
	}
}

func TestRevokingSessionRepository_InvalidatesAllOnRevokeForUser(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "s1", UserID: "u1"})
	src.put(&service.SessionRecord{SID: "s2", UserID: "u1"})
	cache := NewSessionCache(src, time.Minute, nil)
	wrap := WrapSessionRepository(&fakeRepo{stub: src}, cache)

	// Warm both entries.
	_, _ = cache.Lookup(context.Background(), "s1")
	_, _ = cache.Lookup(context.Background(), "s2")
	if err := wrap.RevokeSessionsForUser(context.Background(), "u1", 200); err != nil {
		t.Fatal(err)
	}
	// Both sessions now revoked, and the cache was invalidated so the
	// next lookup sees the Revoked state immediately.
	state, _ := cache.Lookup(context.Background(), "s1")
	if state != SessionStateRevoked {
		t.Fatalf("s1 after RevokeForUser: state=%v, want Revoked", state)
	}
}

func TestWrapSessionRepository_NilCacheIsIdentity(t *testing.T) {
	t.Parallel()
	r := &fakeRepo{stub: newStubLookup()}
	got := WrapSessionRepository(r, nil)
	if got != r {
		t.Fatalf("WrapSessionRepository(_, nil) wrapped instead of pass-through")
	}
}

func TestSessionAuthMiddleware_NilCacheFallsBackToAuthMiddleware(t *testing.T) {
	// The contract: passing cache=nil returns the regular AuthMiddleware
	// so the mode=ttl wiring keeps zero overhead. The behaviour is
	// already covered above; this test just exercises the early return.
	t.Parallel()
	kr, _ := newTestKeyRing(t)
	mw := SessionAuthMiddleware(kr, "", "", false, nil)
	if mw == nil {
		t.Fatal("nil-cache middleware = nil")
	}
}

func TestSessionAuthMiddleware_MissingAuthorizationHeader(t *testing.T) {
	t.Parallel()
	kr, _ := newTestKeyRing(t)
	src := newStubLookup()
	cache := NewSessionCache(src, time.Minute, nil)
	mw := SessionAuthMiddleware(kr, "", "", false, cache)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next called without auth header")
	}))
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/Echo", nil)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rw.Code)
	}
}

func TestSessionAuthMiddleware_InvalidToken(t *testing.T) {
	t.Parallel()
	kr, _ := newTestKeyRing(t)
	src := newStubLookup()
	cache := NewSessionCache(src, time.Minute, nil)
	mw := SessionAuthMiddleware(kr, "", "", false, cache)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next called with invalid token")
	}))
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/Echo", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rw.Code)
	}
}

func TestSessionAuthMiddleware_LookupErrorReturns503(t *testing.T) {
	t.Parallel()
	kr, kid := newTestKeyRing(t)
	src := newStubLookup()
	src.err = errors.New("transient repo error")
	cache := NewSessionCache(src, time.Minute, nil)
	mw := SessionAuthMiddleware(kr, "tenant-1", "", false, cache)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next called on lookup error")
	}))
	token := mintTokenWithSID(t, kr, kid, "u1", "tenant-1", "sid-x")
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/Echo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rw.Code)
	}
}

func TestSessionAuthMiddleware_ExemptPath_RevokedSessionStripsHeader(t *testing.T) {
	t.Parallel()
	kr, kid := newTestKeyRing(t)
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "sid-revoked", UserID: "u1", RevokedAtMs: 200})
	cache := NewSessionCache(src, time.Minute, nil)

	var seenUser string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenUser = r.Header.Get("X-Authenticated-User-Id")
	})
	mw := SessionAuthMiddleware(kr, "tenant-1", "", false, cache)(next)

	token := mintTokenWithSID(t, kr, kid, "u1", "tenant-1", "sid-revoked")
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)

	if seenUser != "" {
		t.Fatalf("revoked session on exempt path leaked user id: %q", seenUser)
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("exempt path returned %d, want 200 (exempt paths never reject)", rw.Code)
	}
}

func TestSessionAuthMiddleware_ExemptPath_ActiveSessionSetsHeader(t *testing.T) {
	t.Parallel()
	kr, kid := newTestKeyRing(t)
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "sid-ok", UserID: "u1"})
	cache := NewSessionCache(src, time.Minute, nil)
	var seenUser string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenUser = r.Header.Get("X-Authenticated-User-Id")
	})
	mw := SessionAuthMiddleware(kr, "tenant-1", "", false, cache)(next)
	token := mintTokenWithSID(t, kr, kid, "u1", "tenant-1", "sid-ok")
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)
	if seenUser != "u1" {
		t.Fatalf("exempt + active session: header = %q, want u1", seenUser)
	}
}

func TestSessionAuthMiddleware_ExemptPath_TokenWithoutSIDSetsHeader(t *testing.T) {
	t.Parallel()
	kr, kid := newTestKeyRing(t)
	src := newStubLookup()
	cache := NewSessionCache(src, time.Minute, nil)
	var seenUser string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenUser = r.Header.Get("X-Authenticated-User-Id")
	})
	mw := SessionAuthMiddleware(kr, "tenant-1", "", false, cache)(next)
	token := mintTokenWithSID(t, kr, kid, "u1", "tenant-1", "")
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	mw.ServeHTTP(rw, req)
	if seenUser != "u1" {
		t.Fatalf("exempt + no-sid: header = %q, want u1", seenUser)
	}
}

// TestSessionCache_SlowPathConcurrentRefiller covers the
// "concurrent refiller already won the lock" branch in Lookup:
// goroutine B enters the slow path, takes the per-sid mutex, and
// the deadline is already in the future because goroutine A
// populated the entry while B was queueing for the lock.
//
// We can't reliably reproduce that interleaving from outside Lookup,
// so this test wires the conditions directly: an entry is
// hand-populated with a future deadline, the Load fast path is then
// stale (a stale-deadline raw.(*cacheEntry) on the first Load), and
// Lookup re-enters the slow path. The re-check in the slow path then
// observes the fresh deadline that the prior population put there.
//
// Wiring detail: we expire the fast-path entry by stamping a
// deadline that is in the past from the perspective of the fast
// path's first `entry.deadline.After(now)` (using start time = now)
// but in the future from the slow path's `entry.deadline.After(c.now())`
// (called with the cache's now func). The cache uses time.Now under
// the hood, so we can't easily override the clock — but we CAN
// pre-populate the entry with a future deadline AND a stale fast-path
// load by inserting into the entries sync.Map and calling Lookup with
// a deadline that the fast path missed because `now` was captured
// before c.now() advanced. That's flaky in practice; for coverage
// we use the simpler equivalent: drive enough concurrent goroutines
// that the scheduler interleaves them past the fast path. With
// GOMAXPROCS=N goroutines, the second Lookup hits the slow path
// re-check on every run when the cache is empty + just populated.
func TestSessionCache_SlowPathConcurrentRefiller(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "race", UserID: "u1"})
	cache := NewSessionCache(src, time.Minute, nil)

	// Drive N goroutines concurrently against the same sid with an
	// empty cache. Exactly one wins the LoadOrStore "create" path; the
	// rest take the per-sid lock after that goroutine populates the
	// deadline and observe the now-future deadline on the re-check.
	const N = 32
	results := make(chan SessionState, N)
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			<-start
			state, _ := cache.Lookup(context.Background(), "race")
			results <- state
		}()
	}
	close(start)
	for i := 0; i < N; i++ {
		if state := <-results; state != SessionStateActive {
			t.Errorf("goroutine %d saw state=%v, want Active", i, state)
		}
	}
	// The repo was hit exactly once across the race.
	if got := src.reads.Load(); got != 1 {
		t.Fatalf("concurrent slow path reads = %d, want 1", got)
	}
}

// TestSessionCache_StaleFastPathHitsSlowPathRecheck exercises the
// "slow-path re-check finds a valid deadline" branch in Lookup. The
// branch is normally hit when goroutine A populates an entry while
// goroutine B was queueing for the per-sid mutex; rather than
// reproduce that interleaving by hand, we drive Lookup against an
// entry whose deadline equals the fast-path snapshot (`now`) — which
// fails the `After(now)` predicate — and then stub c.now so the
// slow-path re-check is called with a strictly earlier moment.
// The deadline IS After that earlier moment so the re-check returns
// the cached state without reading the repo.
func TestSessionCache_StaleFastPathHitsSlowPathRecheck(t *testing.T) {
	t.Parallel()
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "stale", UserID: "u1"})
	cache := NewSessionCache(src, time.Minute, nil)

	t0 := time.Now()
	// Stubbed clock:
	//   call 1 (start of Lookup)               → t0
	//   call 2 (slow-path entry.deadline check) → t0 minus 1ms
	// Real time never moves backwards, but the slow-path re-check is
	// called against c.now() after the lock acquisition; in the real
	// world that's monotonically later than the fast-path snapshot
	// and the re-check serves a fresher deadline that another
	// goroutine just wrote. We simulate the equivalent state by
	// returning a c.now() that PRE-dates the entry's deadline.
	var calls int
	cache.now = func() time.Time {
		calls++
		switch calls {
		case 1:
			return t0
		case 2:
			return t0.Add(-time.Millisecond)
		default:
			return t0.Add(time.Minute)
		}
	}

	// Hand-write the cache entry so the fast path fails the
	// After(now=t0) predicate (deadline == t0) and the slow path's
	// re-check (now=t0-1ms) succeeds (deadline t0 IS After t0-1ms).
	cache.entries.Store("stale", &cacheEntry{
		rec:      &service.SessionRecord{SID: "stale"},
		deadline: t0,
	})

	state, err := cache.Lookup(context.Background(), "stale")
	if err != nil || state != SessionStateActive {
		t.Fatalf("Lookup(stale): state=%v err=%v", state, err)
	}
	// The slow-path re-check served from the existing entry — no repo
	// read should have happened.
	if got := src.reads.Load(); got != 0 {
		t.Fatalf("StaleFastPath unexpected reads = %d, want 0", got)
	}
}

// TestOutcomeLabel covers the cache-state → metric-label mapping
// exhaustively. The middleware reads this from both hit and miss
// paths, so a wrong arm shows up as a mis-bucketed Prometheus label
// rather than as a test failure — exercise every branch directly.
func TestOutcomeLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		state SessionState
		err   error
		hit   bool
		want  string
	}{
		{"error", SessionStateActive, errors.New("boom"), false, "error"},
		{"hit_active", SessionStateActive, nil, true, "hit"},
		{"hit_revoked", SessionStateRevoked, nil, true, "hit_revoked"},
		{"miss_active", SessionStateActive, nil, false, "miss"},
		{"miss_revoked", SessionStateRevoked, nil, false, "miss_revoked"},
		{"missing", SessionStateMissing, nil, false, "missing"},
		{"hit_missing", SessionStateMissing, nil, true, "missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := outcomeLabel(c.state, c.err, c.hit); got != c.want {
				t.Errorf("outcomeLabel(%v, %v, %v) = %q, want %q", c.state, c.err, c.hit, got, c.want)
			}
		})
	}
}

func TestStateFromEntry(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		e    *cacheEntry
		want SessionState
	}{
		{"missing", &cacheEntry{missing: true}, SessionStateMissing},
		{"revoked", &cacheEntry{rec: &service.SessionRecord{RevokedAtMs: 1}}, SessionStateRevoked},
		{"active", &cacheEntry{rec: &service.SessionRecord{}}, SessionStateActive},
		{"empty", &cacheEntry{}, SessionStateActive},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stateFromEntry(c.e); got != c.want {
				t.Errorf("stateFromEntry(%+v) = %v, want %v", c.e, got, c.want)
			}
		})
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────

// BenchmarkSessionLookup_WarmCache measures the warm-cache hot path.
// The DoD requires < 1µs per RPC vs. mode=ttl in this configuration.
func BenchmarkSessionLookup_WarmCache(b *testing.B) {
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "warm", UserID: "u"})
	cache := NewSessionCache(src, 60*time.Second, nil)

	// Prime the cache.
	if _, err := cache.Lookup(context.Background(), "warm"); err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Lookup(ctx, "warm")
	}
}

// BenchmarkSessionLookup_TTLMode_Zero serves as the baseline: in
// mode=ttl the cache is nil and Lookup short-circuits to "active"
// without consulting any state.
func BenchmarkSessionLookup_TTLMode_Zero(b *testing.B) {
	var cache *SessionCache // nil — mode=ttl semantics
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Lookup(ctx, "warm")
	}
}

// ── Helpers ───────────────────────────────────────────────────────────

func newTestKeyRing(tb testing.TB) (*jwttest.Signer, string) {
	tb.Helper()
	s := jwttest.NewSigner(tb, "test-kid")
	return s, "test-kid"
}

func mintTokenWithSID(tb testing.TB, kr *jwttest.Signer, kid, sub, tenant, sid string) string {
	tb.Helper()
	tok, err := kr.SignAccessToken(context.Background(), jwt.Claims{
		Sub:    sub,
		Tenant: tenant,
		SID:    sid,
		Email:  sub + "@example.com",
		Role:   "member",
	}, 5*time.Minute)
	if err != nil {
		tb.Fatalf("SignAccessToken: %v", err)
	}
	_ = kid
	return tok
}
