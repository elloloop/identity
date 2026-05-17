package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

// ── Full middleware chain integration tests ─────────────────────────────

// chainHandler wraps the middleware stack: CORS -> Health -> JWKS -> Auth -> handler.
func chainHandler(t *testing.T, kr jwtpkg.Signer, allowedOrigins string, inner http.Handler) http.Handler {
	t.Helper()
	parsed, err := ParseAllowedOrigins(allowedOrigins, true)
	if err != nil {
		t.Fatalf("ParseAllowedOrigins: %v", err)
	}
	h := inner
	h = AuthMiddleware(kr, "", "", false)(h)
	h = JWKSMiddleware(kr)(h)
	h = HealthMiddleware(nil, h)
	h = CORSMiddleware(parsed)(h)
	return h
}

func TestIntegration_UnauthenticatedExemptPath_PassesThrough(t *testing.T) {
	kr := testSigner(t)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/PasswordLogin", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, userID)
}

func TestIntegration_UnauthenticatedProtectedPath_Returns401(t *testing.T) {
	kr := testSigner(t)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestIntegration_ValidJWT_InjectsUserIDHeader(t *testing.T) {
	kr := testSigner(t)
	token := testToken(t, kr, "user-chain-42", 15*time.Minute)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "user-chain-42", userID)
}

func TestIntegration_ExpiredJWT_Returns401(t *testing.T) {
	kr := testSigner(t)
	token := testToken(t, kr, "user-expired", -1*time.Second)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestIntegration_CORSPreflight_Returns204(t *testing.T) {
	kr := testSigner(t)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodOptions, "/identity.IdentityService/UpdateProfile", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "http://localhost:9002", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "authorization")
	assert.False(t, called, "handler should not be called for preflight")
}

func TestIntegration_CORSDisallowedOrigin_NoAccessControlHeaders(t *testing.T) {
	kr := testSigner(t)
	token := testToken(t, kr, "user-cors", 15*time.Minute)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestIntegration_Health_ReturnsStatusOK(t *testing.T) {
	kr := testSigner(t)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
	assert.False(t, called, "inner handler should not be called for /health")
}

func TestIntegration_JWKS_ReturnsValidJWKS(t *testing.T) {
	kr := testSigner(t)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Cache-Control"), "public")
	assert.False(t, called, "inner handler should not be called for JWKS")

	// Validate JWKS JSON structure.
	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	err := json.Unmarshal(rec.Body.Bytes(), &jwks)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, "test-kid", jwks.Keys[0]["kid"])
	assert.Equal(t, "RSA", jwks.Keys[0]["kty"])
}

func TestIntegration_FullRequestThroughChain(t *testing.T) {
	kr := testSigner(t)
	token := testToken(t, kr, "full-chain-user", 15*time.Minute)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "full-chain-user", userID)
	assert.Equal(t, "http://localhost:9002", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestIntegration_HealthzPath_ReturnsOK(t *testing.T) {
	kr := testSigner(t)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestIntegration_RootPath_ReturnsOK(t *testing.T) {
	kr := testSigner(t)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002", echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestIntegration_MultipleOrigins_AllAllowed(t *testing.T) {
	kr := testSigner(t)
	token := testToken(t, kr, "user-multi", 15*time.Minute)
	var called bool
	var userID string

	handler := chainHandler(t, kr, "http://localhost:9002, http://localhost:3000", echoHandler(&called, &userID))

	for _, origin := range []string{"http://localhost:9002", "http://localhost:3000"} {
		called = false
		userID = ""

		req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.True(t, called, "handler should be called for origin %s", origin)
		assert.Equal(t, origin, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}
