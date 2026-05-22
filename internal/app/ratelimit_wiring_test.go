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
		"/identity.IdentityService/RequestEmailLoginCode",
		"/identity.IdentityService/RequestMagicLink",
	} {
		require.Contains(t, byPath, p, "passwordless path %s must have a rate limit", p)
	}

	handler := middleware.RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, p := range []string{
		"/identity.IdentityService/RequestEmailLoginCode",
		"/identity.IdentityService/RequestMagicLink",
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
