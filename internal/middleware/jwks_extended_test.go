package middleware

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// TestJWKSMiddleware_NonJWKSPath_PassesThrough verifies that requests for
// other paths fall through to the next handler.
func TestJWKSMiddleware_NonJWKSPath_PassesThrough(t *testing.T) {
	t.Parallel()

	kr := testSigner(t)
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
// path: when the rendering fails (e.g. a key has an invalid RSA public key
// that jwk.FromRaw rejects), the middleware must respond with 500 and not
// fall through to the next handler.
func TestJWKSMiddleware_InvalidPublicKey_Returns500(t *testing.T) {
	t.Parallel()

	// A KeyProvider whose Keys() advertises a malformed RSA public key
	// (nil modulus). jwk.FromRaw rejects this without panicking, hitting
	// the rendering error path.
	bad := badKeyProvider{}
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	handler := JWKSMiddleware(bad)(inner)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, called, "inner handler must not be reached on JWKS error")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "internal")
}

// badKeyProvider returns a malformed RSA public key so JWKS rendering fails.
type badKeyProvider struct{}

func (badKeyProvider) Keys() []jwtpkg.PublicKey {
	return []jwtpkg.PublicKey{{
		KID: "bad-kid",
		Key: &rsa.PublicKey{N: nil, E: 0},
	}}
}

func (badKeyProvider) Get(_ string) (*rsa.PublicKey, bool) { return nil, false }
