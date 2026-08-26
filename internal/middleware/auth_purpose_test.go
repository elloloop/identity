package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
)

// purposeToken mints a single-purpose bearer credential (e.g. a
// dob_completion ticket): a fully valid signed JWT whose only distinguishing
// mark is the purpose claim.
func purposeToken(t *testing.T, s *jwttest.Signer, sub string) string {
	t.Helper()
	return purposeTokenOf(t, s, sub, "dob_completion")
}

func purposeTokenOf(t *testing.T, s *jwttest.Signer, sub, purpose string) string {
	t.Helper()
	token, err := s.SignAccessToken(context.Background(), jwtpkg.Claims{
		Sub:     sub,
		Email:   "test@example.com",
		Role:    "member",
		Tenant:  "tenant-1",
		Purpose: purpose,
	}, 10*time.Minute)
	require.NoError(t, err)
	return token
}

// A purpose token is NOT a session: on a JWT-enforced path it is rejected
// exactly like a bad token, even though it verifies.
func TestAuthMiddleware_PurposeToken_RequiredPath_Returns401(t *testing.T) {
	kr := testSigner(t)
	token := purposeToken(t, kr, "user-1")
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/UpdateProfile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called, "a purpose token must never authenticate a request")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid or expired access token")
}

// On an exempt path a purpose token is parsed but never surfaces an
// authenticated identity — the request proceeds as anonymous.
func TestAuthMiddleware_PurposeToken_ExemptPath_NoIdentityInjected(t *testing.T) {
	kr := testSigner(t)
	token := purposeToken(t, kr, "user-1")
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called, "exempt path should still pass through")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, userID, "a purpose token must not inject an authenticated identity")
}

// SubmitDateOfBirth is the one RPC the ticket exists for: it must be
// JWT-exempt or the completion step would be unreachable (the caller has no
// session yet by definition).
func TestAuthMiddleware_SubmitDateOfBirth_Exempt(t *testing.T) {
	kr := testSigner(t)
	var called bool
	var userID string

	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))

	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/SubmitDateOfBirth", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called, "SubmitDateOfBirth must be JWT-exempt")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// In mode=session the purpose-token refusal is identical: a purpose token
// is rejected before any session lookup, even one carrying an active sid.
func TestSessionAuthMiddleware_PurposeToken_Rejected(t *testing.T) {
	kr, _ := newTestKeyRing(t)
	src := newStubLookup()
	src.put(&service.SessionRecord{SID: "sid-purpose", UserID: "user-1"})
	cache := NewSessionCache(src, 60*time.Second, nil)

	token := purposeToken(t, kr, "user-1")

	// Required path: rejected like a bad token.
	var called bool
	var userID string
	handler := SessionAuthMiddleware(kr, "tenant-1", "", false, cache)(echoHandler(&called, &userID))
	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/UpdateProfile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.False(t, called, "a purpose token must never authenticate a request in mode=session")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Exempt path: passes through with no authenticated identity.
	called, userID = false, ""
	req = httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.True(t, called)
	assert.Empty(t, userID, "a purpose token must not inject an authenticated identity in mode=session")
}

// A passkey_enrolment ticket (the managed-child bootstrap credential) is a
// purpose token like any other: as a Bearer credential it authenticates
// NOTHING. On the registration ceremony paths — now JWT-exempt so the child's
// device can call them sessionless, presenting the ticket in the BODY — the
// request passes through anonymous; on any other path it is rejected exactly
// like a bad token.
func TestAuthMiddleware_PasskeyEnrolmentTicket_NeverAuthenticates(t *testing.T) {
	kr := testSigner(t)
	token := purposeTokenOf(t, kr, "child-1", "passkey_enrolment")

	for _, path := range []string{
		"/identity.v1.IdentityService/BeginPasskeyRegistration",
		"/identity.v1.IdentityService/CompletePasskeyRegistration",
	} {
		var called bool
		var userID string
		handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.True(t, called, "%s is JWT-exempt (the ticket rides in the body)", path)
		assert.Empty(t, userID, "a purpose token must not inject an authenticated identity on %s", path)
	}

	var called bool
	var userID string
	handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))
	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/UpdateProfile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.False(t, called, "a purpose token must never authenticate a request")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// A sessionless call to the registration ceremony paths must still REACH the
// handler (which then refuses it itself): the paths are exempt so the
// enrolment-ticket body credential can work at all.
func TestAuthMiddleware_PasskeyRegistrationPaths_Exempt(t *testing.T) {
	kr := testSigner(t)
	for _, path := range []string{
		"/identity.v1.IdentityService/BeginPasskeyRegistration",
		"/identity.v1.IdentityService/CompletePasskeyRegistration",
	} {
		var called bool
		var userID string
		handler := AuthMiddleware(kr, "", "", false)(echoHandler(&called, &userID))
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.True(t, called, "%s must be JWT-exempt for sessionless enrolment", path)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}
