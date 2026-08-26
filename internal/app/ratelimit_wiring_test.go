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

// TestBuildRateLimits_IDVBeginLimited asserts the identity-verification
// begin RPC carries a per-IP quota and returns 429 once exceeded. Every
// admitted call opens a paid provider session, so without the quota the
// spend is caller-driven — the service-level anonymous refusal bounds who
// can call it, this bounds how hard.
func TestBuildRateLimits_IDVBeginLimited(t *testing.T) {
	const path = "/identity.v1.IdentityService/BeginIdentityVerification"
	cfg := &config.Config{
		RateLimitWindowSeconds: 60,
		RateLimitIDVPerIP:      2,
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
	require.Contains(t, byPath, path, "IDV begin path must have a rate limit")

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
	assert.Equal(t, http.StatusOK, codes[0], "IDV begin req 1")
	assert.Equal(t, http.StatusOK, codes[1], "IDV begin req 2")
	assert.Equal(t, http.StatusTooManyRequests, codes[2], "IDV begin req 3 over quota")
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

// TestBuildRateLimits_ManagedMinorPathsLimited asserts the endpoints the
// managed-minor epic added are metered. Two distinct hazards: every one of
// them verifies a step-up password (a bcrypt) before it can refuse, so an
// unmetered path is an unthrottled password-guessing oracle against a stolen
// session; and CreateManagedChildAccount additionally inserts a user row per
// admitted call, the same unbounded row-insert primitive SignInAnonymously is
// quota'd for.
func TestBuildRateLimits_ManagedMinorPathsLimited(t *testing.T) {
	cfg := &config.Config{
		RateLimitWindowSeconds: 60,
		RateLimitSignupPerIP:   2,
		RateLimitLoginPerIP:    2,
		// Other quotas non-zero so unrelated paths stay enabled.
		RateLimitResetPerIP:        5,
		RateLimitVerifyPerIP:       20,
		RateLimitPasswordlessPerIP: 5,
		RateLimitPhonePerIP:        5,
		RateLimitBootstrapPerIP:    5,
	}
	limits := buildRateLimits(cfg)

	byPath := map[string]middleware.PathLimit{}
	for _, l := range limits {
		byPath[l.PathPrefix] = l
	}
	metered := []string{
		"/identity.v1.IdentityService/CreateManagedChildAccount",
		"/identity.v1.IdentityService/SubmitDateOfBirth",
		"/identity.v1.IdentityService/BeginPasskeyRegistration",
		"/identity.v1.IdentityService/CompletePasskeyRegistration",
		"/identity.v1.IdentityService/GrantParentalConsent",
	}
	metered = append(metered, guardianManagementPaths...)
	for _, p := range metered {
		require.Contains(t, byPath, p, "path %s must carry a rate limit", p)
	}

	handler := middleware.RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Account creation is metered on its own budget.
	assertQuotaExhausts(t, handler, "/identity.v1.IdentityService/CreateManagedChildAccount", "7.7.7.7", 2)

	// The seven guardian-management RPCs share ONE budget: two calls to
	// different RPCs exhaust it, and the third is refused whichever RPC it
	// hits. That is the point of the shared tag — the surface is capped as a
	// whole, not seven times over.
	shared := middleware.RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	codes := make([]int, 0, 3)
	for _, p := range guardianManagementPaths[:3] {
		req := httptest.NewRequest(http.MethodPost, p, nil)
		req.Header.Set(middleware.ClientIPHeader, "8.8.8.8")
		w := httptest.NewRecorder()
		shared.ServeHTTP(w, req)
		codes = append(codes, w.Code)
	}
	assert.Equal(t, []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests}, codes,
		"the guardian-management surface shares one per-IP budget")
}

// assertQuotaExhausts drives quota+1 requests at path from one IP and asserts
// the last is refused.
func assertQuotaExhausts(t *testing.T, handler http.Handler, path, ip string, quota int) {
	t.Helper()
	for i := 0; i < quota; i++ {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set(middleware.ClientIPHeader, ip)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "%s request %d must be admitted", path, i+1)
	}
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set(middleware.ClientIPHeader, ip)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "%s must refuse over quota", path)
}
