package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// membershipRepo is a minimal service.Repository fake that answers only
// ListOrganizationsForUser — the single method the tenant resolver
// calls. memberships maps userID → the org slugs they belong to in this
// repo's (tenant's) scope.
type membershipRepo struct {
	service.Repository
	tenant      string
	memberships map[string][]string // userID → org slugs
	err         error
}

func (r *membershipRepo) ListOrganizationsForUser(_ context.Context, userID string) ([]*service.Organization, error) {
	if r.err != nil {
		return nil, r.err
	}
	var out []*service.Organization
	for _, slug := range r.memberships[userID] {
		out = append(out, &service.Organization{Slug: slug})
	}
	return out, nil
}

// scopeCapture records the tenant scope the downstream handler sees.
type scopeCapture struct {
	called bool
	scope  *service.TenantScope
}

func (c *scopeCapture) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.called = true
		c.scope = service.TenantScopeFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func multiCfg(sources string) *config.Config {
	return &config.Config{
		IdentityMode:            config.IdentityModeMulti,
		TenantHostBaseDomain:    "glassa.work",
		TenantResolutionSources: sources,
		DefaultTenantID:         "system",
	}
}

func factoryFor(repos map[string]*membershipRepo) service.RepositoryForTenant {
	return func(tenantID string) service.Repository {
		if r, ok := repos[tenantID]; ok {
			return r
		}
		return &membershipRepo{tenant: tenantID, memberships: map[string][]string{}}
	}
}

func TestTenantResolver_SingleMode_PassThrough(t *testing.T) {
	cfg := &config.Config{IdentityMode: config.IdentityModeSingle, DefaultTenantID: "local"}
	cap := &scopeCapture{}
	h := NewTenantResolver(cfg, nil, nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Host = "acmecorp.glassa.work"
	req.Header.Set(AuthenticatedUserIDHeader, "u1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.True(t, cap.called)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, cap.scope, "single mode must inject no tenant scope (DefaultTenantID is a clean constant)")
}

func TestTenantResolver_ResolvesFromHost_MemberOK(t *testing.T) {
	repos := map[string]*membershipRepo{
		"acmecorp": {tenant: "acmecorp", memberships: map[string][]string{"u1": {"acmecorp"}}},
	}
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host,jwt"), factoryFor(repos), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Host = "acmecorp.glassa.work"
	req.Header.Set(AuthenticatedUserIDHeader, "u1")
	req.Header.Set(AuthenticatedTenantHeader, "acmecorp")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, cap.called)
	require.NotNil(t, cap.scope)
	assert.Equal(t, "acmecorp", cap.scope.TenantID)
	assert.NotNil(t, cap.scope.Repo)
}

func TestTenantResolver_ResolvesFromJWT_WhenHostHasNoSubdomain(t *testing.T) {
	repos := map[string]*membershipRepo{
		"acmecorp": {tenant: "acmecorp", memberships: map[string][]string{"u1": {"acmecorp"}}},
	}
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host,jwt"), factoryFor(repos), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	// Apex domain: host yields no tenant, so jwt source wins.
	req.Host = "glassa.work"
	req.Header.Set(AuthenticatedUserIDHeader, "u1")
	req.Header.Set(AuthenticatedTenantHeader, "acmecorp")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, cap.scope)
	assert.Equal(t, "acmecorp", cap.scope.TenantID)
}

func TestTenantResolver_JWTOnlySource(t *testing.T) {
	repos := map[string]*membershipRepo{
		"acmecorp": {tenant: "acmecorp", memberships: map[string][]string{"u1": {"acmecorp"}}},
	}
	cap := &scopeCapture{}
	cfg := multiCfg("jwt")
	cfg.TenantHostBaseDomain = "" // host source disabled, base domain irrelevant
	h := NewTenantResolver(cfg, factoryFor(repos), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Host = "anything.example.com"
	req.Header.Set(AuthenticatedUserIDHeader, "u1")
	req.Header.Set(AuthenticatedTenantHeader, "acmecorp")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, cap.scope)
	assert.Equal(t, "acmecorp", cap.scope.TenantID)
}

func TestTenantResolver_RejectsNonMember(t *testing.T) {
	repos := map[string]*membershipRepo{
		// u1 is NOT a member of acmecorp's tenant.
		"acmecorp": {tenant: "acmecorp", memberships: map[string][]string{}},
	}
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host,jwt"), factoryFor(repos), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Host = "acmecorp.glassa.work"
	req.Header.Set(AuthenticatedUserIDHeader, "u1")
	req.Header.Set(AuthenticatedTenantHeader, "acmecorp")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, cap.called, "handler must not run when membership check fails")
}

func TestTenantResolver_RejectsHostJWTMismatch(t *testing.T) {
	repos := map[string]*membershipRepo{
		"acmecorp": {tenant: "acmecorp", memberships: map[string][]string{"u1": {"acmecorp"}}},
		"evilcorp": {tenant: "evilcorp", memberships: map[string][]string{"u1": {"evilcorp"}}},
	}
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host,jwt"), factoryFor(repos), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	// Host says acmecorp, token says evilcorp — cross-tenant reuse.
	req.Host = "acmecorp.glassa.work"
	req.Header.Set(AuthenticatedUserIDHeader, "u1")
	req.Header.Set(AuthenticatedTenantHeader, "evilcorp")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, cap.called)
}

func TestTenantResolver_AuthenticatedRequiresResolvedTenant(t *testing.T) {
	cap := &scopeCapture{}
	// host source only; apex domain resolves nothing → authenticated
	// request must be rejected.
	h := NewTenantResolver(multiCfg("host"), factoryFor(nil), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Host = "glassa.work"
	req.Header.Set(AuthenticatedUserIDHeader, "u1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, cap.called)
}

func TestTenantResolver_UnauthenticatedLoginGetsHostScope_NoMemberCheck(t *testing.T) {
	// PasswordLogin: no authenticated user yet, but the request must be
	// scoped to the host tenant so the service finds the user there. No
	// membership check (the user isn't authenticated).
	repos := map[string]*membershipRepo{
		"acmecorp": {tenant: "acmecorp", memberships: map[string][]string{}},
	}
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host,jwt"), factoryFor(repos), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/PasswordLogin", nil)
	req.Host = "acmecorp.glassa.work"
	// No AuthenticatedUserIDHeader — unauthenticated.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, cap.called)
	require.NotNil(t, cap.scope)
	assert.Equal(t, "acmecorp", cap.scope.TenantID)
}

func TestTenantResolver_OrganizationSignup_PassesThroughNoScope(t *testing.T) {
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host,jwt"), factoryFor(nil), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/OrganizationSignup", nil)
	req.Host = "glassa.work" // apex — tenant doesn't exist yet
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, cap.called)
	assert.Nil(t, cap.scope, "OrganizationSignup creates the tenant; it gets no resolved scope")
}

func TestTenantResolver_UnauthenticatedNoTenant_PassesThroughNoScope(t *testing.T) {
	// An unauthenticated request that resolves no tenant (e.g. a JWKS
	// fetch on the apex domain) passes through with no scope rather than
	// being rejected — authenticated paths require a tenant, these don't.
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host"), factoryFor(nil), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodGet, "/identity.IdentityService/GetCurrentUser", nil)
	req.Host = "glassa.work" // apex — no tenant; no user header — unauthenticated
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, cap.called)
	assert.Nil(t, cap.scope, "unauthenticated + unresolved tenant must carry no scope")
}

// nilFactory returns a factory whose lookup always yields a nil
// Repository, simulating a tenant the backend cannot serve.
func nilFactory() service.RepositoryForTenant {
	return func(string) service.Repository { return nil }
}

func TestTenantResolver_AuthenticatedNilRepo_Unavailable(t *testing.T) {
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host"), nilFactory(), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Host = "acmecorp.glassa.work"
	req.Header.Set(AuthenticatedUserIDHeader, "u1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, cap.called)
}

func TestTenantResolver_UnauthenticatedNilRepo_Unavailable(t *testing.T) {
	// serveWithScope's nil-repo guard: an unauthenticated, host-scoped
	// path (login) against a tenant whose repo is unavailable.
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host"), nilFactory(), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/PasswordLogin", nil)
	req.Host = "acmecorp.glassa.work"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, cap.called)
}

func TestTenantResolver_MembershipCheckError_Unavailable(t *testing.T) {
	repos := map[string]*membershipRepo{
		"acmecorp": {tenant: "acmecorp", err: errors.New("backend down")},
	}
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host"), factoryFor(repos), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Host = "acmecorp.glassa.work"
	req.Header.Set(AuthenticatedUserIDHeader, "u1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, cap.called)
}

func TestTenantResolver_HostParsing_EmptyBaseDomain(t *testing.T) {
	// With no base domain configured, host parsing yields no tenant
	// regardless of the request host (the host source is effectively
	// disabled; Validate rejects this combination at boot).
	tr := &TenantResolver{sources: []string{config.TenantSourceHost}, baseDomain: ""}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "acmecorp.glassa.work"
	assert.Equal(t, "", tr.tenantFromHost(req))
}

func TestTenantResolver_HostParsing(t *testing.T) {
	tr := &TenantResolver{sources: []string{config.TenantSourceHost}, baseDomain: "glassa.work"}
	cases := []struct {
		host string
		want string
	}{
		{"acmecorp.glassa.work", "acmecorp"},
		{"acmecorp.glassa.work:8443", "acmecorp"},
		{"ACMECORP.GLASSA.WORK", "acmecorp"},
		{"glassa.work", ""},       // apex
		{"a.b.glassa.work", ""},   // nested label, not a tenant
		{"other.example.com", ""}, // unrelated host
		{"", ""},                  // empty
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = c.host
		got := tr.tenantFromHost(req)
		assert.Equal(t, c.want, got, "host=%q", c.host)
	}
}

func TestTenantResolver_StripsSpoofedHeaders(t *testing.T) {
	// The auth middleware strips inbound identity headers; this verifies
	// the resolver does not trust a client-supplied scope header. The
	// scope only ever comes from the resolver itself via context.
	cap := &scopeCapture{}
	h := NewTenantResolver(multiCfg("host"), factoryFor(map[string]*membershipRepo{
		"acmecorp": {tenant: "acmecorp", memberships: map[string][]string{"u1": {"acmecorp"}}},
	}), nil)(cap.handler())

	req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/GetCurrentUser", nil)
	req.Host = "acmecorp.glassa.work"
	req.Header.Set(AuthenticatedUserIDHeader, "u1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, cap.scope)
	assert.Equal(t, "acmecorp", cap.scope.TenantID)
}
