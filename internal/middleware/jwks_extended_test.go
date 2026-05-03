package middleware

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// TestJWKSMiddleware_NonJWKSPath_PassesThrough verifies that requests for
// other paths fall through to the next handler.
func TestJWKSMiddleware_NonJWKSPath_PassesThrough(t *testing.T) {
	t.Parallel()

	kr := testKeyRing(t)
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := JWKSMiddleware(kr)(inner)

	req := httptest.NewRequest(http.MethodGet, "/some/other/path", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestJWKSMiddleware_InvalidPublicKey_Returns500 exercises the JWKS error
// path: when KeyRing.JWKS() fails (e.g. a key has an invalid RSA public key
// that jwk.FromRaw rejects), the middleware must respond with 500 and not
// fall through to the next handler.
func TestJWKSMiddleware_InvalidPublicKey_Returns500(t *testing.T) {
	t.Parallel()

	// rsa.PublicKey with nil N is rejected by jwk.FromRaw with an error
	// (no panic) — perfect for triggering KeyRing.JWKS()'s error path.
	bad := jwtpkg.SigningKey{
		KID:        "bad-kid",
		PrivateKey: nil,
		PublicKey:  &rsa.PublicKey{N: nil, E: 0},
		Active:     true,
	}
	kr, err := jwtpkg.NewKeyRing([]jwtpkg.SigningKey{bad})
	require.NoError(t, err)

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	handler := JWKSMiddleware(kr)(inner)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, called, "inner handler must not be reached on JWKS error")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "internal")
}
