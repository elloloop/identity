package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nopHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func mustParse(t *testing.T, raw string) []string {
	t.Helper()
	out, err := ParseAllowedOrigins(raw, true)
	require.NoError(t, err)
	return out
}

func TestCORS_AllowedOrigin_SetsHeaders(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002,http://localhost:3000"))(nopHandler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "http://localhost:9002", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "grpc-status,grpc-message", rec.Header().Get("Access-Control-Expose-Headers"))
}

func TestCORS_DisallowedOrigin_NoHeaders(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	assert.Empty(t, rec.Header().Get("Access-Control-Expose-Headers"))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCORS_OriginCaseMismatch_Rejected(t *testing.T) {
	cases := []struct{ name, origin string }{
		{"uppercase host", "http://LOCALHOST:9002"},
		{"mixed case host", "http://LocalHost:9002"},
		{"uppercase scheme", "HTTP://localhost:9002"},
	}
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set("Origin", tc.origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestCORS_PortDifference_Rejected(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "http://localhost:9003")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_Preflight_Returns204(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "http://localhost:9002", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_Preflight_SetsAllowMethods(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/identity.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, "POST, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "authorization")
	assert.Equal(t, "86400", rec.Header().Get("Access-Control-Max-Age"))
}

func TestCORS_Preflight_DisallowedOrigin_StillReturns204(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/some-path", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_NoOriginHeader_PassesThroughUnchanged(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodPost, "/some-path", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestParseAllowedOrigins_WildcardWithCredentials_Rejected(t *testing.T) {
	cases := []string{"*", "http://localhost:9002,*", "*,http://localhost:9002", " * "}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseAllowedOrigins(raw, true)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "wildcard")
		})
	}
}

func TestParseAllowedOrigins_NullOriginWithCredentials_Rejected(t *testing.T) {
	_, err := ParseAllowedOrigins("http://localhost:9002,null", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "null")
}

func TestParseAllowedOrigins_EmptyEntryWithCredentials_Rejected(t *testing.T) {
	_, err := ParseAllowedOrigins("http://localhost:9002,", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty origin entry")
}

func TestParseAllowedOrigins_EmptyList_Rejected(t *testing.T) {
	_, err := ParseAllowedOrigins("", true)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAllowedOriginsEmpty))
}

func TestParseAllowedOrigins_MalformedOrigin_Rejected(t *testing.T) {
	cases := []string{
		"localhost:9002",            // missing scheme
		"ftp://localhost:9002",      // wrong scheme
		"http://localhost:9002/",    // trailing slash
		"http://localhost:9002/x",   // path
		"http://localhost:9002?q=1", // query
		"http://localhost:9002#f",   // fragment
		"http://user@localhost",     // userinfo
		"HTTP://localhost:9002",     // uppercase scheme
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseAllowedOrigins(raw, true)
			require.Error(t, err)
		})
	}
}

func TestParseAllowedOrigins_ValidList_PreservesOrderAndCase(t *testing.T) {
	out, err := ParseAllowedOrigins("https://A.example.com,http://localhost:9002 , https://b.example.com", true)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://A.example.com", "http://localhost:9002", "https://b.example.com"}, out)
}
