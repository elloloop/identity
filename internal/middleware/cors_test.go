package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func nopHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestCORS_AllowedOrigin_SetsHeaders(t *testing.T) {
	handler := CORSMiddleware("http://localhost:9002,http://localhost:3000")(nopHandler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "http://localhost:9002", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "grpc-status,grpc-message", rec.Header().Get("Access-Control-Expose-Headers"))
}

func TestCORS_DisallowedOrigin_NoHeaders(t *testing.T) {
	handler := CORSMiddleware("http://localhost:9002")(nopHandler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	assert.Empty(t, rec.Header().Get("Access-Control-Expose-Headers"))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCORS_Preflight_Returns204(t *testing.T) {
	handler := CORSMiddleware("http://localhost:9002")(nopHandler())

	req := httptest.NewRequest(http.MethodOptions, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "http://localhost:9002", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_Preflight_SetsAllowMethods(t *testing.T) {
	handler := CORSMiddleware("http://localhost:9002")(nopHandler())

	req := httptest.NewRequest(http.MethodOptions, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "POST, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "authorization")
	assert.Equal(t, "86400", rec.Header().Get("Access-Control-Max-Age"))
}

func TestCORS_Preflight_DisallowedOrigin_StillReturns204(t *testing.T) {
	handler := CORSMiddleware("http://localhost:9002")(nopHandler())

	req := httptest.NewRequest(http.MethodOptions, "/some-path", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Preflight always returns 204 but without Allow-Origin.
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_NoOriginHeader_NoHeaders(t *testing.T) {
	handler := CORSMiddleware("http://localhost:9002")(nopHandler())

	req := httptest.NewRequest(http.MethodPost, "/some-path", nil)
	// No Origin header set.
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusOK, rec.Code)
}
