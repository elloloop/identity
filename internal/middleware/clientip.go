package middleware

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ClientIPHeader is set by ClientIPMiddleware to the resolved client IP.
// Downstream handlers (audit log, rate limiter) read this header instead
// of X-Forwarded-For so they cannot be spoofed.
const ClientIPHeader = "X-Client-IP"

type clientIPCtxKey struct{}

// ParseTrustedProxies parses a comma-separated list of CIDRs. Whitespace
// around entries is ignored. The empty string returns an empty slice,
// meaning "trust no proxies" — X-Forwarded-For is ignored entirely and
// only the TCP peer address is honoured.
func ParseTrustedProxies(raw string) ([]*net.IPNet, error) {
	out := []*net.IPNet{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Allow plain IPs (treated as /32 or /128).
		if !strings.Contains(p, "/") {
			ip := net.ParseIP(p)
			if ip == nil {
				return nil, fmt.Errorf("trusted_proxies: invalid entry %q", p)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			p = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, cidr, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: %q: %w", p, err)
		}
		out = append(out, cidr)
	}
	return out, nil
}

// ClientIPMiddleware resolves the client IP by walking X-Forwarded-For
// right-to-left, skipping any addresses that themselves come from a
// trusted proxy CIDR. The first untrusted address is the real client.
// If no XFF is present or no trusted proxies are configured, falls back
// to the TCP peer address.
//
// The resolved IP is set on both the X-Client-IP header (for downstream
// handlers that read headers) and on the request context.
func ClientIPMiddleware(trusted []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolveClientIP(r, trusted)
			r.Header.Set(ClientIPHeader, ip)
			ctx := context.WithValue(r.Context(), clientIPCtxKey{}, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClientIPFromContext returns the resolved client IP stored by
// ClientIPMiddleware. Returns "" if the middleware did not run.
func ClientIPFromContext(ctx context.Context) string {
	v, _ := ctx.Value(clientIPCtxKey{}).(string)
	return v
}

func resolveClientIP(r *http.Request, trusted []*net.IPNet) string {
	peer := stripPort(r.RemoteAddr)
	if len(trusted) == 0 || !ipIn(peer, trusted) {
		return peer
	}
	// Peer is a trusted proxy; honour X-Forwarded-For. Walk
	// right-to-left, stopping at the first untrusted hop.
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if candidate == "" {
			continue
		}
		if !ipIn(candidate, trusted) {
			return candidate
		}
	}
	// All hops are trusted — fall back to the left-most entry.
	return strings.TrimSpace(parts[0])
}

func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func ipIn(addr string, nets []*net.IPNet) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ErrInvalidTrustedProxy is returned by ParseTrustedProxies for entries
// the parser cannot interpret.
var ErrInvalidTrustedProxy = errors.New("invalid trusted proxy entry")
