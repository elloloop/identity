package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFixedWindowLimiter_AllowsUpToLimit(t *testing.T) {
	l := NewFixedWindowLimiter(time.Minute, 3, 0)
	now := time.Now()
	for i := 0; i < 3; i++ {
		assert.True(t, l.Allow("a", now), "allow %d", i)
	}
	assert.False(t, l.Allow("a", now), "fourth call must be denied")
}

func TestFixedWindowLimiter_DifferentKeysIndependent(t *testing.T) {
	l := NewFixedWindowLimiter(time.Minute, 1, 0)
	now := time.Now()
	assert.True(t, l.Allow("a", now))
	assert.True(t, l.Allow("b", now))
	assert.False(t, l.Allow("a", now))
}

func TestFixedWindowLimiter_NewWindowResets(t *testing.T) {
	l := NewFixedWindowLimiter(50*time.Millisecond, 1, 0)
	t0 := time.Now()
	assert.True(t, l.Allow("a", t0))
	assert.False(t, l.Allow("a", t0))
	assert.True(t, l.Allow("a", t0.Add(60*time.Millisecond)))
}

func TestFixedWindowLimiter_ZeroLimitDisables(t *testing.T) {
	l := NewFixedWindowLimiter(time.Minute, 0, 0)
	for i := 0; i < 1000; i++ {
		assert.True(t, l.Allow("a", time.Now()))
	}
}

func TestRateLimitMiddleware_Returns429_OverLimit(t *testing.T) {
	l := NewFixedWindowLimiter(time.Minute, 2, 0)
	limits := []PathLimit{{
		PathPrefix: "/identity.v1.IdentityService/PasswordSignup",
		Tag:        "signup",
		Limiter:    l,
	}}
	called := 0
	handler := RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	// Two successful requests then a 429 on the third.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/PasswordSignup", nil)
		req.Header.Set(ClientIPHeader, "1.2.3.4")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if i < 2 {
			assert.Equal(t, http.StatusOK, rec.Code, "i=%d", i)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, rec.Code)
			assert.Equal(t, "60", rec.Header().Get("Retry-After"))
		}
	}
	assert.Equal(t, 2, called)
}

func TestRateLimitMiddleware_DifferentIPsCounted_Separately(t *testing.T) {
	l := NewFixedWindowLimiter(time.Minute, 1, 0)
	limits := []PathLimit{{PathPrefix: "/x", Tag: "x", Limiter: l}}
	handler := RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodPost, "/x/foo", nil)
	req1.Header.Set(ClientIPHeader, "1.1.1.1")
	r1 := httptest.NewRecorder()
	handler.ServeHTTP(r1, req1)
	assert.Equal(t, http.StatusOK, r1.Code)

	req2 := httptest.NewRequest(http.MethodPost, "/x/foo", nil)
	req2.Header.Set(ClientIPHeader, "2.2.2.2")
	r2 := httptest.NewRecorder()
	handler.ServeHTTP(r2, req2)
	assert.Equal(t, http.StatusOK, r2.Code)

	// Both IPs over budget on third call.
	req3 := httptest.NewRequest(http.MethodPost, "/x/foo", nil)
	req3.Header.Set(ClientIPHeader, "1.1.1.1")
	r3 := httptest.NewRecorder()
	handler.ServeHTTP(r3, req3)
	assert.Equal(t, http.StatusTooManyRequests, r3.Code)
}

func TestRateLimitMiddleware_NoClientIPHeader_FailsOpen(t *testing.T) {
	l := NewFixedWindowLimiter(time.Minute, 1, 0)
	limits := []PathLimit{{PathPrefix: "/x", Tag: "x", Limiter: l}}
	handler := RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/x/foo", nil)
		// No ClientIPHeader.
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestRateLimitMiddleware_NonMatchingPath_Bypasses(t *testing.T) {
	l := NewFixedWindowLimiter(time.Minute, 1, 0)
	limits := []PathLimit{{PathPrefix: "/x", Tag: "x", Limiter: l}}
	handler := RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header.Set(ClientIPHeader, "1.1.1.1")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestFixedWindowLimiter_EvictsOldEntries(t *testing.T) {
	l := NewFixedWindowLimiter(50*time.Millisecond, 5, 2)
	now := time.Now()
	for _, k := range []string{"a", "b"} {
		assert.True(t, l.Allow(k, now))
	}
	// Now insert "c"; with maxSize=2 the limiter has to evict.
	// First it tries to drop entries whose window expired; advance
	// the clock past the window so "a" and "b" are evictable.
	assert.True(t, l.Allow("c", now.Add(60*time.Millisecond)))
}

func TestFixedWindowLimiter_EvictsArbitraryWhenAllWithinWindow(t *testing.T) {
	l := NewFixedWindowLimiter(time.Minute, 5, 2)
	now := time.Now()
	assert.True(t, l.Allow("a", now))
	assert.True(t, l.Allow("b", now))
	// All entries still within window; eviction has to drop one
	// arbitrary entry to fit "c".
	assert.True(t, l.Allow("c", now))
}

func TestFixedWindowLimiter_NilReceiverAlwaysAllows(t *testing.T) {
	var l *FixedWindowLimiter
	assert.True(t, l.Allow("a", time.Now()))
}
