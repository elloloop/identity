package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTrustedProxies_AcceptsValid(t *testing.T) {
	out, err := ParseTrustedProxies("10.0.0.0/8, 192.168.0.0/16,127.0.0.1, ::1")
	require.NoError(t, err)
	assert.Len(t, out, 4)
}

func TestParseTrustedProxies_RejectsInvalid(t *testing.T) {
	_, err := ParseTrustedProxies("notanip")
	require.Error(t, err)
}

func TestParseTrustedProxies_EmptyReturnsEmpty(t *testing.T) {
	out, err := ParseTrustedProxies("")
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestClientIP_NoTrustedProxies_UsesPeer(t *testing.T) {
	trusted, _ := ParseTrustedProxies("")
	handler := ClientIPMiddleware(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get(ClientIPHeader)))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:55555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, "203.0.113.10", rec.Body.String())
}

func TestClientIP_TrustedPeer_HonorsXFF(t *testing.T) {
	trusted, _ := ParseTrustedProxies("10.0.0.0/8")
	handler := ClientIPMiddleware(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get(ClientIPHeader)))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:80"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.7")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, "1.2.3.4", rec.Body.String(),
		"should walk right-to-left, skipping trusted hops")
}

func TestClientIP_UntrustedPeer_IgnoresXFF(t *testing.T) {
	trusted, _ := ParseTrustedProxies("10.0.0.0/8")
	handler := ClientIPMiddleware(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get(ClientIPHeader)))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:80" // untrusted public IP
	req.Header.Set("X-Forwarded-For", "spoofed-attacker-ip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, "203.0.113.10", rec.Body.String(),
		"untrusted peer's XFF must be ignored")
}
