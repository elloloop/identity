package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
)

// TestBuildRateLimits_PasswordlessPathsLimited asserts the two
// passwordless Request endpoints are wired to the per-IP passwordless
// quota — the spam control the issue requires — and actually return 429
// once the quota is exceeded.
func TestBuildRateLimits_PasswordlessPathsLimited(t *testing.T) {
	cfg := &config.Config{
		RateLimitWindowSeconds:     60,
		RateLimitPasswordlessPerIP: 2,
		// Other quotas non-zero so unrelated paths stay enabled.
		RateLimitSignupPerIP: 10,
		RateLimitLoginPerIP:  30,
		RateLimitResetPerIP:  5,
		RateLimitVerifyPerIP: 20,
	}
	limits := buildRateLimits(cfg)

	byPath := map[string]middleware.PathLimit{}
	for _, l := range limits {
		byPath[l.PathPrefix] = l
	}
	for _, p := range []string{
		"/identity.v1.IdentityService/RequestEmailLoginCode",
		"/identity.v1.IdentityService/RequestMagicLink",
	} {
		require.Contains(t, byPath, p, "passwordless path %s must have a rate limit", p)
	}

	handler := middleware.RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, p := range []string{
		"/identity.v1.IdentityService/RequestEmailLoginCode",
		"/identity.v1.IdentityService/RequestMagicLink",
	} {
		codes := make([]int, 3)
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest(http.MethodPost, p, nil)
			req.Header.Set(middleware.ClientIPHeader, "9.9.9.9")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			codes[i] = w.Code
		}
		assert.Equal(t, http.StatusOK, codes[0], "%s req 1", p)
		assert.Equal(t, http.StatusOK, codes[1], "%s req 2", p)
		assert.Equal(t, http.StatusTooManyRequests, codes[2], "%s req 3 over quota", p)
	}
}

// TestBuildRateLimits_FirstAdminBootstrapLimited asserts the ungated
// first-admin bootstrap RPC is wired to the per-IP bootstrap quota and
// returns 429 once exceeded — so the one non-secret-gated admin endpoint
// cannot be hammered while it is open on a fresh deployment.
func TestBuildRateLimits_FirstAdminBootstrapLimited(t *testing.T) {
	const path = "/identity.v1.IdentityService/CreateFirstPlatformAdmin"
	cfg := &config.Config{
		RateLimitWindowSeconds:  60,
		RateLimitBootstrapPerIP: 2,
		// Other quotas non-zero so unrelated paths stay enabled.
		RateLimitSignupPerIP:       10,
		RateLimitLoginPerIP:        30,
		RateLimitResetPerIP:        5,
		RateLimitVerifyPerIP:       20,
		RateLimitPasswordlessPerIP: 5,
		RateLimitPhonePerIP:        5,
	}
	limits := buildRateLimits(cfg)

	byPath := map[string]middleware.PathLimit{}
	for _, l := range limits {
		byPath[l.PathPrefix] = l
	}
	require.Contains(t, byPath, path, "bootstrap path must have a rate limit")

	handler := middleware.RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	codes := make([]int, 3)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set(middleware.ClientIPHeader, "9.9.9.9")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		codes[i] = w.Code
	}
	assert.Equal(t, http.StatusOK, codes[0], "bootstrap req 1")
	assert.Equal(t, http.StatusOK, codes[1], "bootstrap req 2")
	assert.Equal(t, http.StatusTooManyRequests, codes[2], "bootstrap req 3 over quota")
}

// TestBuildRateLimits_AssurancePathsLimited asserts the three
// client-assurance endpoints carry a per-IP quota. They are JWT-exempt, and
// the exchange paths each spend an outbound provider request (Turnstile /
// reCAPTCHA siteverify, Google decodeIntegrityToken) plus an RSA signature
// and an audit row, while the challenge path writes a DB row — so an
// unlimited path would let an anonymous caller drive third-party quota,
// storage growth and outbound amplification.
func TestBuildRateLimits_AssurancePathsLimited(t *testing.T) {
	cfg := &config.Config{
		RateLimitWindowSeconds:  60,
		RateLimitAssurancePerIP: 2,
		// Other quotas non-zero so unrelated paths stay enabled.
		RateLimitSignupPerIP:       10,
		RateLimitLoginPerIP:        30,
		RateLimitResetPerIP:        5,
		RateLimitVerifyPerIP:       20,
		RateLimitPasswordlessPerIP: 5,
	}
	limits := buildRateLimits(cfg)

	byPath := map[string]middleware.PathLimit{}
	for _, l := range limits {
		byPath[l.PathPrefix] = l
	}
	assurancePaths := []string{
		"/identity.v1.IdentityService/CreateAssuranceChallenge",
		"/identity.v1.IdentityService/IssueAssuranceToken",
		"/identity.v1.IdentityService/RefreshAssuranceToken",
	}
	for _, p := range assurancePaths {
		require.Contains(t, byPath, p, "assurance path %s must have a rate limit", p)
	}

	handler := middleware.RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, p := range assurancePaths {
		codes := make([]int, 3)
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest(http.MethodPost, p, nil)
			req.Header.Set(middleware.ClientIPHeader, "203.0.113.9")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}
		assert.Equal(t, http.StatusOK, codes[0], "%s first request", p)
		assert.Equal(t, http.StatusOK, codes[1], "%s second request", p)
		assert.Equal(t, http.StatusTooManyRequests, codes[2], "%s must 429 past the quota", p)
	}
}
