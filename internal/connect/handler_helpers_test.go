package connect

import (
	"net/http"
	"testing"
)

// TestClientIP covers the trusted-proxy resolution order: the
// middleware-set X-Client-IP wins, with X-Forwarded-For then X-Real-Ip
// as fallbacks for tests / pre-middleware paths, and "" when none are
// present.
func TestClientIP(t *testing.T) {
	cases := []struct {
		name string
		hdr  http.Header
		want string
	}{
		{"x-client-ip wins", http.Header{"X-Client-Ip": {"1.1.1.1"}, "X-Forwarded-For": {"2.2.2.2"}}, "1.1.1.1"},
		{"forwarded-for fallback", http.Header{"X-Forwarded-For": {"2.2.2.2"}, "X-Real-Ip": {"3.3.3.3"}}, "2.2.2.2"},
		{"real-ip last resort", http.Header{"X-Real-Ip": {"3.3.3.3"}}, "3.3.3.3"},
		{"none present", http.Header{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientIP(tc.hdr); got != tc.want {
				t.Fatalf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthenticatedUserIDAndUserAgent(t *testing.T) {
	h := http.Header{"X-Authenticated-User-Id": {"user-1"}, "User-Agent": {"agent/1.0"}}
	if got := authenticatedUserID(h); got != "user-1" {
		t.Fatalf("authenticatedUserID() = %q, want %q", got, "user-1")
	}
	if got := clientUserAgent(h); got != "agent/1.0" {
		t.Fatalf("clientUserAgent() = %q, want %q", got, "agent/1.0")
	}
	// Absent headers return "".
	if got := authenticatedUserID(http.Header{}); got != "" {
		t.Fatalf("authenticatedUserID(empty) = %q, want \"\"", got)
	}
}
