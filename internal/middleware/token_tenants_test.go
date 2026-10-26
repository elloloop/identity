package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/service"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
)

const (
	ttDefault = "storage-default"
	ttProject = "proj-acme"
	ttPath    = "/identity.v1.IdentityService/GetProfile"
)

// fakeTenantLookup serves tenants keyed by project and id.
type fakeTenantLookup struct {
	byKey map[string]*service.Tenant
	err   error
	calls int
}

func (f *fakeTenantLookup) GetTenantStatus(_ context.Context, projectID, tenantID string) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	if t := f.byKey[projectID+"/"+tenantID]; t != nil {
		return t.Status, nil
	}
	return "", nil
}

func newTenantLookup() *fakeTenantLookup {
	return &fakeTenantLookup{byKey: map[string]*service.Tenant{
		ttProject + "/t-claimed":   {ID: "t-claimed", ProjectID: ttProject, Status: service.TenantStatusClaimed},
		ttProject + "/t-suspended": {ID: "t-suspended", ProjectID: ttProject, Status: service.TenantStatusSuspended},
		ttProject + "/t-latent":    {ID: "t-latent", ProjectID: ttProject, Status: service.TenantStatusLatent},
		"proj-other/t-elsewhere":   {ID: "t-elsewhere", ProjectID: "proj-other", Status: service.TenantStatusClaimed},
	}}
}

func tenantToken(t *testing.T, s *jwttest.Signer, project, tenant string) string {
	t.Helper()
	token, err := s.SignAccessToken(context.Background(), jwtpkg.Claims{
		Sub: "user-1", Email: "user@example.test", Role: "member", Project: project, Tenant: tenant,
	}, 5*time.Minute)
	require.NoError(t, err)
	return token
}

// tenantCapture records what the handler behind the middleware saw.
type tenantCapture struct {
	called bool
	userID string
	tenant string
}

func (c *tenantCapture) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.called = true
		c.userID = r.Header.Get(AuthenticatedUserIDHeader)
		c.tenant = r.Header.Get(AuthenticatedTenantHeader)
		w.WriteHeader(http.StatusOK)
	})
}

func serveWithToken(h http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Both the plain and the session-aware middleware apply the same rule.
func tokenTenantMiddlewares(signer *jwttest.Signer, tenants TokenTenants) map[string]func(http.Handler) http.Handler {
	return map[string]func(http.Handler) http.Handler{
		"auth":    AuthMiddleware(signer, tenants, "", false),
		"session": SessionAuthMiddleware(signer, tenants, "", false, NewSessionCache(newStubLookup(), 0, nil)),
	}
}

func TestTokenTenants_AcceptsDefaultAndSelectedClaimedTenant(t *testing.T) {
	signer := testSigner(t)
	lookup := newTenantLookup()
	for name, mw := range tokenTenantMiddlewares(signer, TokenTenants{Default: ttDefault, Selectable: lookup}) {
		t.Run(name, func(t *testing.T) {
			for _, tenant := range []string{ttDefault, "t-claimed"} {
				cap := &tenantCapture{}
				rec := serveWithToken(mw(cap.handler()), ttPath, tenantToken(t, signer, ttProject, tenant))
				require.Equal(t, http.StatusOK, rec.Code, "tenant %q", tenant)
				assert.Equal(t, "user-1", cap.userID)
				assert.Equal(t, tenant, cap.tenant, "the handler sees the token's tenant")
			}
		})
	}
}

func TestTokenTenants_DefaultNeedsNoLookup(t *testing.T) {
	signer := testSigner(t)
	lookup := newTenantLookup()
	cap := &tenantCapture{}
	mw := AuthMiddleware(signer, TokenTenants{Default: ttDefault, Selectable: lookup}, "", false)
	rec := serveWithToken(mw(cap.handler()), ttPath, tenantToken(t, signer, ttProject, ttDefault))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Zero(t, lookup.calls, "a default-tenant token is accepted without a read")
}

func TestTokenTenants_RefusesTenantsTheRuleDoesNotAccept(t *testing.T) {
	signer := testSigner(t)
	cases := map[string]struct {
		project, tenant string
	}{
		"unknown tenant":              {ttProject, "t-missing"},
		"suspended tenant":            {ttProject, "t-suspended"},
		"latent tenant":               {ttProject, "t-latent"},
		"another project's tenant":    {ttProject, "t-elsewhere"},
		"selected without a project":  {"", "t-claimed"},
		"no tenant claim":             {ttProject, ""},
		"default of another instance": {ttProject, "storage-other"},
	}
	for name, mw := range tokenTenantMiddlewares(signer, TokenTenants{Default: ttDefault, Selectable: newTenantLookup()}) {
		for caseName, tc := range cases {
			t.Run(name+"/"+caseName, func(t *testing.T) {
				cap := &tenantCapture{}
				rec := serveWithToken(mw(cap.handler()), ttPath, tenantToken(t, signer, tc.project, tc.tenant))
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.False(t, cap.called)
			})
		}
	}
}

func TestTokenTenants_WithoutSelectableOnlyDefault(t *testing.T) {
	signer := testSigner(t)
	for name, mw := range tokenTenantMiddlewares(signer, TokenTenants{Default: ttDefault}) {
		t.Run(name, func(t *testing.T) {
			cap := &tenantCapture{}
			rec := serveWithToken(mw(cap.handler()), ttPath, tenantToken(t, signer, ttProject, "t-claimed"))
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.False(t, cap.called)
		})
	}
}

func TestTokenTenants_ZeroValueAcceptsAnyTenant(t *testing.T) {
	signer := testSigner(t)
	for name, mw := range tokenTenantMiddlewares(signer, TokenTenants{}) {
		t.Run(name, func(t *testing.T) {
			cap := &tenantCapture{}
			rec := serveWithToken(mw(cap.handler()), ttPath, tenantToken(t, signer, ttProject, "anything"))
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

// A failed read of a selected tenant is not a verdict on the token: a
// non-exempt request is answered 503, and an exempt one goes on
// unauthenticated.
func TestTokenTenants_LookupErrorIsUnavailable(t *testing.T) {
	signer := testSigner(t)
	lookup := newTenantLookup()
	lookup.err = errors.New("database down")
	for name, mw := range tokenTenantMiddlewares(signer, TokenTenants{Default: ttDefault, Selectable: lookup}) {
		t.Run(name, func(t *testing.T) {
			token := tenantToken(t, signer, ttProject, "t-claimed")

			cap := &tenantCapture{}
			rec := serveWithToken(mw(cap.handler()), ttPath, token)
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
			assert.Contains(t, rec.Body.String(), `"unavailable"`)
			assert.False(t, cap.called)

			cap = &tenantCapture{}
			rec = serveWithToken(mw(cap.handler()), "/identity.v1.IdentityService/PasswordLogin", token)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.True(t, cap.called)
			assert.Empty(t, cap.userID, "an exempt path does not authenticate an unverified tenant")
		})
	}
}

// The 503 is logged with the tenant it was for and the cause, never the token.
func TestTokenTenants_LookupErrorIsLoggedWithoutTheToken(t *testing.T) {
	signer := testSigner(t)
	lookup := newTenantLookup()
	lookup.err = errors.New("database down")
	core, logs := observer.New(zap.WarnLevel)
	mw := AuthMiddleware(signer, TokenTenants{Default: ttDefault, Selectable: lookup, Logger: zap.New(core)}, "", false)
	token := tenantToken(t, signer, ttProject, "t-claimed")

	rec := serveWithToken(mw((&tenantCapture{}).handler()), ttPath, token)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	entries := logs.FilterMessage("token_tenant_lookup_failed").All()
	require.Len(t, entries, 1)
	fields := entries[0].ContextMap()
	assert.Equal(t, ttProject, fields["project_id"])
	assert.Equal(t, "t-claimed", fields["tenant_id"])
	assert.Equal(t, "database down", fields["error"])
	for key, v := range fields {
		assert.NotContains(t, fmt.Sprint(v), token, "field %s must not carry the token", key)
	}
}

// On an exempt path a refused tenant leaves the request unauthenticated
// rather than rejecting it.
func TestTokenTenants_ExemptPathIgnoresRefusedToken(t *testing.T) {
	signer := testSigner(t)
	for name, mw := range tokenTenantMiddlewares(signer, TokenTenants{Default: ttDefault, Selectable: newTenantLookup()}) {
		t.Run(name, func(t *testing.T) {
			cap := &tenantCapture{}
			rec := serveWithToken(mw(cap.handler()), "/identity.v1.IdentityService/PasswordLogin", tenantToken(t, signer, ttProject, "t-suspended"))
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Empty(t, cap.userID)
		})
	}
}
