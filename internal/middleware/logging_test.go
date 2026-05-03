package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLoggingMiddleware_LogsRequest(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := LoggingMiddleware(logger)(inner)

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, "request", entry.Message)

	fields := entry.ContextMap()
	assert.Equal(t, http.MethodGet, fields["method"])
	assert.Equal(t, "/some/path", fields["path"])
	assert.EqualValues(t, http.StatusOK, fields["status"])
	assert.Contains(t, fields, "duration")
	assert.Contains(t, fields, "remote_addr")
}

func TestLoggingMiddleware_CapturesNonDefaultStatus(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	handler := LoggingMiddleware(logger)(inner)

	req := httptest.NewRequest(http.MethodPost, "/teapot", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, 1, logs.Len())
	fields := logs.All()[0].ContextMap()
	assert.EqualValues(t, http.StatusTeapot, fields["status"])
	assert.Equal(t, http.StatusTeapot, rec.Code)
}

func TestLoggingMiddleware_DefaultStatusIsOK(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	// Inner handler that does NOT call WriteHeader explicitly. Status should
	// default to 200 because responseWriter pre-sets it.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	handler := LoggingMiddleware(logger)(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, 1, logs.Len())
	fields := logs.All()[0].ContextMap()
	assert.EqualValues(t, http.StatusOK, fields["status"])
}

func TestResponseWriter_WriteHeader_DelegatesAndCaptures(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusForbidden)

	assert.Equal(t, http.StatusForbidden, rw.statusCode)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
