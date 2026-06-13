package middleware

import (
	"net/http"

	"github.com/elloloop/identity/internal/service"
)

// NewProjectScopeGuard rejects a request whose access-token `project` claim
// disagrees with the project resolved for the request — a token minted
// under project A replayed against a request resolved to project B
// (cross-project token reuse). It is the consumer of the project claim,
// the project counterpart to the tenant resolver's host/JWT cross-check.
//
// It must run AFTER the auth middleware (which surfaces the verified
// project as AuthenticatedProjectHeader) and AFTER project resolution
// (which sets the request's ProjectScope). When either side is absent it
// is a pass-through: an unauthenticated request carries no token project,
// and a deployment with no control plane resolves no project scope — so the
// guard never interferes with those paths.
func NewProjectScopeGuard() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scope := service.ProjectScopeFromContext(r.Context())
			tokenProject := r.Header.Get(AuthenticatedProjectHeader)
			if scope != nil && scope.ProjectID != "" && tokenProject != "" && scope.ProjectID != tokenProject {
				writeConnectError(w, http.StatusForbidden, "permission_denied",
					"access token was issued for a different project")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
