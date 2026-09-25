package middleware

import (
	"context"
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

// captureClientIPHandler returns a handler that records the resolved
// client IP into the provided pointer rather than writing it back to
// the response body. Avoids gosec's G705 false-positive on writing
// header-derived bytes to a ResponseWriter in tests.
func captureClientIPHandler(seen *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Get(ClientIPHeader)
		w.WriteHeader(http.StatusOK)
	})
}

func TestClientIP_NoTrustedProxies_UsesPeer(t *testing.T) {
	trusted, _ := ParseTrustedProxies("")
	var got string
	handler := ClientIPMiddleware(trusted)(captureClientIPHandler(&got))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:55555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	assert.Equal(t, "203.0.113.10", got)
}

func TestClientIP_TrustedPeer_HonorsXFF(t *testing.T) {
	trusted, _ := ParseTrustedProxies("10.0.0.0/8")
	var got string
	handler := ClientIPMiddleware(trusted)(captureClientIPHandler(&got))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:80"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.7")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	assert.Equal(t, "1.2.3.4", got,
		"should walk right-to-left, skipping trusted hops")
}

func TestClientIP_UntrustedPeer_IgnoresXFF(t *testing.T) {
	trusted, _ := ParseTrustedProxies("10.0.0.0/8")
	var got string
	handler := ClientIPMiddleware(trusted)(captureClientIPHandler(&got))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:80" // untrusted public IP
	req.Header.Set("X-Forwarded-For", "spoofed-attacker-ip")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	assert.Equal(t, "203.0.113.10", got,
		"untrusted peer's XFF must be ignored")
}

func TestClientIPFromContext_NotSet(t *testing.T) {
	if got := ClientIPFromContext(context.Background()); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestClientIPFromContext_PropagatedByMiddleware(t *testing.T) {
	trusted, _ := ParseTrustedProxies("")
	var seenCtx string
	h := ClientIPMiddleware(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenCtx = ClientIPFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:55555"
	h.ServeHTTP(httptest.NewRecorder(), req)
	assert.Equal(t, "203.0.113.10", seenCtx)
}

func TestStripPort_NoPort(t *testing.T) {
	// SplitHostPort fails on no-port input; stripPort returns the input.
	if got := stripPort("203.0.113.10"); got != "203.0.113.10" {
		t.Fatalf("got %q, want 203.0.113.10", got)
	}
}

func TestResolveClientIP_TrustedPeerEmptyXFF_FallsBackToPeer(t *testing.T) {
	trusted, _ := ParseTrustedProxies("10.0.0.0/8")
	// No XFF header.
	got := ResolveClientIP("10.0.0.5:80", "", trusted)
	assert.Equal(t, "10.0.0.5", got)
}

func TestResolveClientIP_AllTrustedHops_FallsBackToLeftmost(t *testing.T) {
	trusted, _ := ParseTrustedProxies("10.0.0.0/8,192.168.0.0/16")
	got := ResolveClientIP("10.0.0.5:80", "10.0.0.7, 192.168.1.1, 10.0.0.9", trusted)
	assert.Equal(t, "10.0.0.7", got, "all hops trusted; fall back to left-most")
}

func TestResolveClientIP_XFFWithEmptyEntries(t *testing.T) {
	trusted, _ := ParseTrustedProxies("10.0.0.0/8")
	got := ResolveClientIP("10.0.0.5:80", "1.2.3.4, , 10.0.0.7", trusted)
	assert.Equal(t, "1.2.3.4", got, "empty entries skipped, real client returned")
}

// An untrusted peer is the client whatever X-Forwarded-For it sends, so a
// caller cannot pick its own address.
func TestResolveClientIP_UntrustedPeerIgnoresXFF(t *testing.T) {
	trusted, _ := ParseTrustedProxies("10.0.0.0/8")
	assert.Equal(t, "203.0.113.9", ResolveClientIP("203.0.113.9:4000", "1.2.3.4", trusted))
	assert.Equal(t, "203.0.113.9", ResolveClientIP("203.0.113.9:4000", "1.2.3.4", nil))
}

func TestIpIn_ParseFailsReturnsFalse(t *testing.T) {
	trusted, _ := ParseTrustedProxies("10.0.0.0/8")
	assert.False(t, ipIn("not-an-ip", trusted))
}
