package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// serveGuard runs a request through NewProjectScopeGuard with an optional
// injected ProjectScope and X-Authenticated-Project header, returning the
// recorder and whether the downstream handler ran.
func serveGuard(t *testing.T, scope *service.ProjectScope, tokenProject string) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	reached := false
	h := NewProjectScopeGuard()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetCurrentUser", nil)
	if tokenProject != "" {
		req.Header.Set(AuthenticatedProjectHeader, tokenProject)
	}
	if scope != nil {
		req = req.WithContext(service.WithProjectScope(req.Context(), scope))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, reached
}

// A token whose project matches the resolved project passes.
func TestProjectScopeGuard_Match_Passes(t *testing.T) {
	rec, reached := serveGuard(t, &service.ProjectScope{ProjectID: "proj-a"}, "proj-a")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached)
}

// A token minted for a different project than the one resolved is rejected.
func TestProjectScopeGuard_Mismatch_Rejected(t *testing.T) {
	rec, reached := serveGuard(t, &service.ProjectScope{ProjectID: "proj-a"}, "proj-b")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, reached, "a cross-project token must not reach the handler")
}

// An unauthenticated request (no token project) is unaffected, even with a
// resolved project scope.
func TestProjectScopeGuard_NoToken_Passes(t *testing.T) {
	rec, reached := serveGuard(t, &service.ProjectScope{ProjectID: "proj-a"}, "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached)
}

// With no resolved project scope (no control plane), the guard never
// interferes — even when the token carries a project.
func TestProjectScopeGuard_NoScope_Passes(t *testing.T) {
	rec, reached := serveGuard(t, nil, "proj-a")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached)
}
