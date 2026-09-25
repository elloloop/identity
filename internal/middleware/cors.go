package middleware

import (
	"net/http"

	"github.com/elloloop/identity/internal/origin"
	"github.com/elloloop/identity/internal/service"
)

// CORSMiddleware handles CORS preflight requests and injects response headers
// for allowed origins. globalOrigins must be the validated output of
// origin.ParseAllowedOrigins — the deployment-wide floor from
// GATEWAY_ALLOWED_ORIGINS. An exact entry matches case-sensitively on scheme+host+port; a wildcard
// pattern matches one DNS label under its parent (origin.Pattern). The
// response always echoes the concrete request Origin, never a pattern, and
// carries Vary: Origin so a shared cache never serves one origin's CORS
// headers to another.
//
// On top of that floor, a request is matched against the resolved project's
// own allow-list (service.ProjectScope.CORSAllowedOrigins, set by the project
// resolver, already validated): an Origin in EITHER set is allowed. When no
// project resolves (a deployment with no control plane, or a request that
// resolves to no project), only the global floor applies. This middleware must
// run INSIDE the project resolver so the scope is present — including on the
// OPTIONS preflight, which carries no credentials and so relies on Host →
// project resolution (the resolver runs ahead of auth).
func CORSMiddleware(globalOrigins origin.Allowlist) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Vary", "Origin")
			requestOrigin := r.Header.Get("Origin")
			if requestOrigin == "" {
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			allowed := globalOrigins.Allows(requestOrigin) || projectOrigins(r).Allows(requestOrigin)

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", requestOrigin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Expose-Headers", "grpc-status,grpc-message")
			}

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
				// x-project-key carries the publishable project credential (ProjectKeyHeader)
				// that routes a browser request to its control-plane project; without it in
				// the allow-list a cross-origin SPA cannot select a non-default project.
				// x-product (ProductHeader) names the product the request authenticates for,
				// so a browser app is gated by its own product's guardrails rather than
				// silently falling back to the deployment default. x-assurance-token
				// carries the client-assurance token (assurance.HeaderName) the gated
				// auth endpoints require; without it a cross-origin SPA that completed
				// the exchange could never attach the token.
				w.Header().Set("Access-Control-Allow-Headers", "content-type, authorization, connect-protocol-version, connect-timeout-ms, x-user-id, cookie, x-user-agent, x-grpc-web, grpc-timeout, x-project-key, x-product, x-assurance-token")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// projectOrigins returns the resolved project's per-request CORS allow-list,
// or the empty allow-list when no project is in scope. It is the resolver's
// already-validated output, so the middleware adds it to the global floor
// without re-validating.
func projectOrigins(r *http.Request) origin.Allowlist {
	if scope := service.ProjectScopeFromContext(r.Context()); scope != nil {
		return scope.CORSAllowedOrigins
	}
	return origin.Allowlist{}
}
