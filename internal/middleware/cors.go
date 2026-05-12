package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrAllowedOriginsEmpty is returned by ParseAllowedOrigins when the resolved
// list contains no origins.
var ErrAllowedOriginsEmpty = errors.New("cors: no allowed origins configured")

// ParseAllowedOrigins splits a comma-separated origin list and validates each
// entry. When allowCredentials is true the function refuses dangerous values:
// the wildcard "*", literal "null", empty entries, and malformed URLs. The
// returned slice preserves input order and case.
//
// Why: this middleware unconditionally sets Access-Control-Allow-Credentials,
// so a wildcard origin in the allowlist would expose authenticated state to
// any origin. Failing fast at startup is the only safe behaviour.
func ParseAllowedOrigins(raw string, allowCredentials bool) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, ErrAllowedOriginsEmpty
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			if allowCredentials {
				return nil, errors.New("cors: empty origin entry not allowed with credentials")
			}
			continue
		}
		if allowCredentials {
			if p == "*" {
				return nil, errors.New(`cors: wildcard "*" origin not allowed with credentials`)
			}
			if p == "null" {
				return nil, errors.New(`cors: literal "null" origin not allowed with credentials`)
			}
		}
		if err := validateOrigin(p); err != nil {
			return nil, fmt.Errorf("cors: origin %q invalid: %w", p, err)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, ErrAllowedOriginsEmpty
	}
	return out, nil
}

func validateOrigin(s string) error {
	if strings.ContainsAny(s, " \t\r\n") {
		return errors.New("contains whitespace")
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return errors.New("scheme must be lower-case http:// or https://")
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Host == "" {
		return errors.New("host is empty")
	}
	if u.Path != "" {
		return errors.New("path not allowed")
	}
	if u.RawQuery != "" {
		return errors.New("query not allowed")
	}
	if u.Fragment != "" {
		return errors.New("fragment not allowed")
	}
	if u.User != nil {
		return errors.New("userinfo not allowed")
	}
	return nil
}

// CORSMiddleware handles CORS preflight requests and injects response headers
// for allowed origins. allowedOrigins must be the validated output of
// ParseAllowedOrigins. Match is exact case-sensitive on scheme+host+port.
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	origins := make([]string, len(allowedOrigins))
	copy(origins, allowedOrigins)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			allowed := false
			for _, o := range origins {
				if o == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Expose-Headers", "grpc-status,grpc-message")
			}

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "content-type, authorization, connect-protocol-version, connect-timeout-ms, x-user-id, cookie")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
