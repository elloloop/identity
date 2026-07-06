package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/elloloop/identity/internal/service"
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
	return ValidateAllowedOrigins(strings.Split(raw, ","), allowCredentials)
}

// ValidateAllowedOrigins validates an already-split list of origins under the
// same rules as ParseAllowedOrigins. It exists for callers whose origins come
// from a structured source (a project's config_json array) rather than a
// comma-separated env var, so they need not round-trip through a join/split.
// Order and case are preserved; an all-empty input is ErrAllowedOriginsEmpty.
func ValidateAllowedOrigins(origins []string, allowCredentials bool) ([]string, error) {
	out := make([]string, 0, len(origins))
	for _, p := range origins {
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
// for allowed origins. globalOrigins must be the validated output of
// ParseAllowedOrigins — the deployment-wide floor from GATEWAY_ALLOWED_ORIGINS.
// Match is exact case-sensitive on scheme+host+port.
//
// On top of that floor, a request is matched against the resolved project's
// own allow-list (service.ProjectScope.CORSAllowedOrigins, set by the project
// resolver, already validated): an Origin in EITHER set is allowed. When no
// project resolves (a deployment with no control plane, or a request that
// resolves to no project), only the global floor applies. This middleware must
// run INSIDE the project resolver so the scope is present — including on the
// OPTIONS preflight, which carries no credentials and so relies on Host →
// project resolution (the resolver runs ahead of auth).
func CORSMiddleware(globalOrigins []string) func(http.Handler) http.Handler {
	origins := make([]string, len(globalOrigins))
	copy(origins, globalOrigins)

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

			allowed := originAllowed(origin, origins) || originAllowed(origin, projectOrigins(r))

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Expose-Headers", "grpc-status,grpc-message")
			}

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "content-type, authorization, connect-protocol-version, connect-timeout-ms, x-user-id, cookie, x-user-agent, x-grpc-web, grpc-timeout")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// originAllowed reports whether origin exactly matches an entry in list
// (case-sensitive on scheme+host+port, matching the CORS spec's serialized
// origin comparison).
func originAllowed(origin string, list []string) bool {
	for _, o := range list {
		if o == origin {
			return true
		}
	}
	return false
}

// projectOrigins returns the resolved project's per-request CORS allow-list,
// or nil when no project is in scope. The slice is the resolver's
// already-validated output, so the middleware adds it to the global floor
// without re-validating.
func projectOrigins(r *http.Request) []string {
	if scope := service.ProjectScopeFromContext(r.Context()); scope != nil {
		return scope.CORSAllowedOrigins
	}
	return nil
}
