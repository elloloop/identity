package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type stubProbe struct{ err error }

func (s stubProbe) Ready(_ context.Context) error { return s.err }

func TestHealth_LivezReturnsOK(t *testing.T) {
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("inner handler should not be called for /livez")
	})
	handler := HealthMiddleware(nil, inner)

	for _, path := range []string{"/livez", "/health", "/healthz", "/"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
		})
	}
}

func TestHealth_ReadyzNilProbeReturnsOK(t *testing.T) {
	handler := HealthMiddleware(nil, http.NotFoundHandler())
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHealth_ReadyzProbeOK(t *testing.T) {
	handler := HealthMiddleware(stubProbe{}, http.NotFoundHandler())
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHealth_ReadyzProbeFails_Returns503(t *testing.T) {
	handler := HealthMiddleware(stubProbe{err: errors.New("db down")}, http.NotFoundHandler())
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.JSONEq(t, `{"status":"not_ready"}`, rec.Body.String())
}

func TestHealth_OtherPath_PassesThrough(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := HealthMiddleware(nil, inner)

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.True(t, called, "inner handler should be called for non-health paths")
	assert.Equal(t, http.StatusOK, rec.Code)
}
