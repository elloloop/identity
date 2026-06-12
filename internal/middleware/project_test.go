package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// fakeProjectResolver is a table-driven service.ProjectResolver fake:
// byKey / byHost map an input to a resolved project; err forces an
// infrastructure failure on every call.
type fakeProjectResolver struct {
	byKey  map[string]*service.ResolvedProject
	byHost map[string]*service.ResolvedProject
	err    error
}

func (f *fakeProjectResolver) ResolveByCredential(_ context.Context, publicID string) (*service.ResolvedProject, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byKey[publicID], nil
}

func (f *fakeProjectResolver) ResolveByHostname(_ context.Context, hostname string) (*service.ResolvedProject, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byHost[hostname], nil
}

// projectScopeCapture records the project scope the downstream handler sees.
type projectScopeCapture struct {
	called bool
	scope  *service.ProjectScope
}

func (c *projectScopeCapture) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.called = true
		c.scope = service.ProjectScopeFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

const (
	defProjectID = "default"
	defScopeID   = "local"
)

// serve runs a request through NewProjectResolver and returns the recorder
// plus the captured downstream scope.
func serve(t *testing.T, resolver service.ProjectResolver, defaultID, defaultScope string, mutate func(*http.Request)) (*httptest.ResponseRecorder, *projectScopeCapture) {
	t.Helper()
	cap := &projectScopeCapture{}
	h := NewProjectResolver(defaultID, defaultScope, resolver, nil)(cap.handler())
	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, cap
}

// With no resolver (entdb/memory) and no key/host, every request pins to
// the configured default project.
func TestProjectResolver_NilResolver_PinsDefault(t *testing.T) {
	rec, cap := serve(t, nil, defProjectID, defScopeID, nil)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, cap.called)
	require.NotNil(t, cap.scope)
	assert.Equal(t, defProjectID, cap.scope.ProjectID)
	assert.Equal(t, defScopeID, cap.scope.StorageScopeID)
}

// With neither a resolver nor a default project, the middleware is a no-op
// pass-through: no scope, request still served.
func TestProjectResolver_NoResolverNoDefault_PassThrough(t *testing.T) {
	rec, cap := serve(t, nil, "", "", nil)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, cap.called)
	assert.Nil(t, cap.scope, "no resolver and no default project must inject no scope")
}

// A valid credential key resolves its project and takes precedence over
// the Host.
func TestProjectResolver_ResolvesByKey(t *testing.T) {
	resolver := &fakeProjectResolver{
		byKey:  map[string]*service.ResolvedProject{"pk_live": {ID: "proj-a", StorageScopeID: "scope-a"}},
		byHost: map[string]*service.ResolvedProject{"auth.b.test": {ID: "proj-b", StorageScopeID: "scope-b"}},
	}
	rec, cap := serve(t, resolver, defProjectID, defScopeID, func(r *http.Request) {
		r.Header.Set(ProjectKeyHeader, "pk_live")
		r.Host = "auth.b.test" // key must win over host
	})

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, cap.scope)
	assert.Equal(t, "proj-a", cap.scope.ProjectID)
	assert.Equal(t, "scope-a", cap.scope.StorageScopeID)
}

// An explicit but invalid key is rejected (401) — never downgraded to the
// default project.
func TestProjectResolver_InvalidKey_Rejected(t *testing.T) {
	resolver := &fakeProjectResolver{}
	rec, cap := serve(t, resolver, defProjectID, defScopeID, func(r *http.Request) {
		r.Header.Set(ProjectKeyHeader, "pk_bogus")
	})

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, cap.called, "an invalid key must not reach the handler")
}

// The Host resolves a project (case-insensitive, port stripped) when no
// key is present.
func TestProjectResolver_ResolvesByHost(t *testing.T) {
	resolver := &fakeProjectResolver{
		byHost: map[string]*service.ResolvedProject{"auth.acme.test": {ID: "proj-acme", StorageScopeID: "scope-acme"}},
	}
	rec, cap := serve(t, resolver, defProjectID, defScopeID, func(r *http.Request) {
		r.Host = "Auth.Acme.Test:8443"
	})

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, cap.scope)
	assert.Equal(t, "proj-acme", cap.scope.ProjectID)
}

// An unresolved Host (with a resolver present) falls back to the default
// project — the zero-config single-project behavior.
func TestProjectResolver_UnknownHost_FallsBackToDefault(t *testing.T) {
	resolver := &fakeProjectResolver{}
	rec, cap := serve(t, resolver, defProjectID, defScopeID, func(r *http.Request) {
		r.Host = "unknown.test"
	})

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, cap.scope)
	assert.Equal(t, defProjectID, cap.scope.ProjectID)
}

// A resolver present but no default project configured: an unresolved
// request passes through unscoped (the operator explicitly opted out of a
// default-project pin) rather than being rejected.
func TestProjectResolver_ResolverNoDefault_UnknownHost_PassThrough(t *testing.T) {
	resolver := &fakeProjectResolver{}
	rec, cap := serve(t, resolver, "", "", func(r *http.Request) {
		r.Host = "unknown.test"
	})

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, cap.called)
	assert.Nil(t, cap.scope, "no default project: an unresolved request passes through unscoped")
}

// A resolver infrastructure error on the key path surfaces 503, not a
// silent default fallback.
func TestProjectResolver_KeyError_Unavailable(t *testing.T) {
	resolver := &fakeProjectResolver{err: errors.New("db down")}
	rec, cap := serve(t, resolver, defProjectID, defScopeID, func(r *http.Request) {
		r.Header.Set(ProjectKeyHeader, "pk_live")
	})

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, cap.called)
}

// A resolver infrastructure error on the host path surfaces 503.
func TestProjectResolver_HostError_Unavailable(t *testing.T) {
	resolver := &fakeProjectResolver{err: errors.New("db down")}
	rec, cap := serve(t, resolver, defProjectID, defScopeID, func(r *http.Request) {
		r.Host = "auth.acme.test"
	})

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, cap.called)
}
