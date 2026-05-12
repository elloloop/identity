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

// testKeyRing creates a KeyRing with a freshly generated RSA key for testing.
func testKeyRing(t *testing.T) *jwtpkg.KeyRing {
	t.Helper()
	sk, err := jwtpkg.GenerateKey("test-kid")
	require.NoError(t, err)
	kr, err := jwtpkg.NewKeyRing([]jwtpkg.SigningKey{sk})
	require.NoError(t, err)
	return kr
}

// testToken creates a valid signed access token for testing.
func testToken(t *testing.T, kr *jwtpkg.KeyRing, sub string, expiry time.Duration) string {
	t.Helper()
	token, err := jwtpkg.CreateAccessToken(jwtpkg.Claims{
		Sub:    sub,
		Email:  "test@example.com",
		Name:   "Test User",
		Role:   "member",
		Tenant: "tenant-1",
	}, kr, expiry)
	require.NoError(t, err)
	return token
}

// echoHandler is a simple handler that records whether it was called and what
// user-id header was set.
func echoHandler(called *bool, userID *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		*userID = r.Header.Get("X-Authenticated-User-Id")
		w.WriteHeader(http.StatusOK)
	})
}

func TestAuthMiddleware_ExemptPath_NoToken_Passes(t *testing.T) {
	kr := testKeyRing(t)
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called, "handler should have been called")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, userID, "user ID should not be set when no token is provided")
}

func TestAuthMiddleware_BeginOAuthLogin_ExemptNoToken_Passes(t *testing.T) {
	kr := testKeyRing(t)
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/BeginOAuthLogin", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called, "handler should have been called")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, userID)
}

func TestAuthMiddleware_ExemptPath_WithToken_InjectsUserID(t *testing.T) {
	kr := testKeyRing(t)
	token := testToken(t, kr, "user-42", 15*time.Minute)
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "user-42", userID)
}

func TestAuthMiddleware_ExemptPath_InvalidToken_StillPasses(t *testing.T) {
	kr := testKeyRing(t)
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/RefreshToken", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-here")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called, "exempt path should pass even with invalid token")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, userID, "user ID should not be set for invalid token")
}

func TestAuthMiddleware_RequiredPath_NoToken_Returns401(t *testing.T) {
	kr := testKeyRing(t)
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called, "handler should NOT have been called")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Missing Authorization header")
}

func TestAuthMiddleware_RequiredPath_InvalidToken_Returns401(t *testing.T) {
	kr := testKeyRing(t)
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid or expired access token")
}

func TestAuthMiddleware_RequiredPath_ValidToken_InjectsUserID(t *testing.T) {
	kr := testKeyRing(t)
	token := testToken(t, kr, "user-99", 15*time.Minute)
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "user-99", userID)
}

func TestAuthMiddleware_RequiredPath_ExpiredToken_Returns401(t *testing.T) {
	kr := testKeyRing(t)
	// Create a token that has already expired (negative duration effectively means
	// expiry = now - 1s, which is in the past).
	token := testToken(t, kr, "user-expired", -1*time.Second)
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/UpdateProfile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid or expired access token")
}

func TestExtractBearerToken_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer my-token-123")

	got := extractBearerToken(req)
	assert.Equal(t, "my-token-123", got)
}

func TestExtractBearerToken_NoBearer(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"empty", ""},
		{"basic auth", "Basic dXNlcjpwYXNz"},
		{"bearer lowercase", "bearer my-token"},
		{"no space", "BearerNoSpace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			got := extractBearerToken(req)
			assert.Empty(t, got)
		})
	}
}

func TestAuthMiddleware_HealthPath_ExemptNoToken(t *testing.T) {
	kr := testKeyRing(t)
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}
