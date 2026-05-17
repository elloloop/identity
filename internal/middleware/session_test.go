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
