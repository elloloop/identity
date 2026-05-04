package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// recordingHandler returns an http.Handler that records whether it was called.
func recordingHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

// TestSec_HeaderInjection_CRLF asserts that a token containing CR/LF or
// other control characters does not panic and is rejected.
//
// Authorization headers carrying control characters could be used in
// header-smuggling attacks against downstream services. Go's net/http will
// usually strip these on the request side via Header.Set, but we test the
// raw byte path: the AuthMiddleware must not panic and must reject.
func TestSec_HeaderInjection_CRLF(t *testing.T) {
	t.Parallel()
	kr := newSecTestKR(t)

	cases := []struct {
		name string
		val  string
	}{
		{"crlf-in-bearer", "Bearer abc\r\nX-Injected: yes"},
		{"lf-in-bearer", "Bearer abc\ndef"},
		{"cr-in-bearer", "Bearer abc\rdef"},
		{"null-in-bearer", "Bearer abc\x00def"},
		{"vtab-in-bearer", "Bearer abc\vdef"},
		{"esc-in-bearer", "Bearer abc\x1bdef"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var called bool
			h := AuthMiddleware(kr, "")(recordingHandler(&called))

			req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
			// Direct map write bypasses Go's CRLF validation in Header.Set.
			req.Header["Authorization"] = []string{tc.val}
			rec := httptest.NewRecorder()

			// Must not panic.
			require.NotPanics(t, func() { h.ServeHTTP(rec, req) })
			assert.False(t, called, "control-char auth header MUST NOT pass through")
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		})
	}
}

// TestSec_BearerSmuggling asserts the middleware doesn't accept malformed
// Authorization headers like "Bearer  Bearer X" or lowercase "bearer X".
func TestSec_BearerSmuggling(t *testing.T) {
	t.Parallel()
	kr := newSecTestKR(t)
	good := mintToken(t, kr, "user-1")

	cases := []struct {
		name      string
		header    string
		wantAllow bool
	}{
		{"double-bearer", "Bearer  Bearer " + good, false},
		{"lowercase-bearer", "bearer " + good, false},
		{"mixed-case-bearer", "BeArEr " + good, false},
		{"trailing-whitespace-after-bearer", "Bearer " + good + "    ", false},
		{"leading-whitespace", "  Bearer " + good, false},
		{"bearer-no-space", "Bearer" + good, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var called bool
			h := AuthMiddleware(kr, "")(recordingHandler(&called))

			req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
			req.Header.Set("Authorization", tc.header)
			rec := httptest.NewRecorder()

			require.NotPanics(t, func() { h.ServeHTTP(rec, req) })
			if tc.wantAllow {
				assert.True(t, called, "expected handler to be called for %q", tc.header)
			} else {
				assert.False(t, called, "expected reject for %q", tc.header)
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
			}
		})
	}
}

// TestSec_EmptyOrMalformedAuth_NoPanic asserts that empty or weirdly-shaped
// Authorization headers are handled cleanly — no panics, predictable 401s.
func TestSec_EmptyOrMalformedAuth_NoPanic(t *testing.T) {
	t.Parallel()
	kr := newSecTestKR(t)

	cases := []struct {
		name   string
		header string
	}{
		{"missing", ""},
		{"only-bearer", "Bearer"},
		{"bearer-space", "Bearer "},
		{"bearer-only-spaces", "Bearer       "},
		{"basic-auth", "Basic dXNlcjpwYXNz"},
		{"random-junk", "garbage..."},
		{"only-dots", "..."},
		{"single-char", "x"},
		{"long-no-bearer", "ThisIsNotABearerToken1234567890"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var called bool
			h := AuthMiddleware(kr, "")(recordingHandler(&called))

			req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()

			require.NotPanics(t, func() { h.ServeHTTP(rec, req) })
			assert.False(t, called, "malformed auth MUST NOT pass through")
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "expected 401 for %q", tc.header)
		})
	}
}

// TestSec_BearerCaseSensitive_Required documents that the scheme MUST be
// exactly "Bearer " — RFC 6750 says the scheme is case-insensitive, but
// our implementation is strictly case-sensitive. This test pins the
// stricter behavior; if RFC 6750 case-insensitivity is intentionally
// added, update this test.
func TestSec_BearerCaseSensitive_Required(t *testing.T) {
	t.Parallel()
	kr := newSecTestKR(t)
	good := mintToken(t, kr, "user-1")

	var called bool
	h := AuthMiddleware(kr, "")(recordingHandler(&called))
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
	req.Header.Set("Authorization", "bearer "+good)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	assert.False(t, called, "lowercase 'bearer' is rejected by current implementation")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ---- helpers (kept private to this file to avoid clashing with auth_test.go) ----

func newSecTestKR(t *testing.T) *jwtpkg.KeyRing {
	t.Helper()
	sk, err := jwtpkg.GenerateKey("sec-test-kid")
	require.NoError(t, err)
	kr, err := jwtpkg.NewKeyRing([]jwtpkg.SigningKey{sk})
	require.NoError(t, err)
	return kr
}

func mintToken(t *testing.T, kr *jwtpkg.KeyRing, sub string) string {
	t.Helper()
	tok, err := jwtpkg.CreateAccessToken(jwtpkg.Claims{
		Sub:    sub,
		Email:  "u@example.com",
		Name:   "U",
		Role:   "member",
		Tenant: "t1",
	}, kr, 15*time.Minute)
	require.NoError(t, err)
	return tok
}
