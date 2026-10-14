package service_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func validRegistration() *service.OAuthClientRegistration {
	return &service.OAuthClientRegistration{Name: "Acme desktop", RedirectURIs: []string{"http://127.0.0.1/callback", "http://[::1]/callback", "https://app.example.test/callback?mode=native"}, Resources: []service.OAuthResourceBounds{{Resource: "https://api.example.test/", Scopes: []string{"records:read", "records:write"}}}, GrantTypes: []string{service.OAuthGrantAuthorizationCode, service.OAuthGrantRefreshToken}}
}

func TestOAuthClientRegistrationValidation(t *testing.T) {
	require.NoError(t, validRegistration().Validate())
	require.ErrorIs(t, (*service.OAuthClientRegistration)(nil).Validate(), service.ErrInvalidArgument)
	cases := map[string]func(*service.OAuthClientRegistration){
		"empty name":         func(r *service.OAuthClientRegistration) { r.Name = " " },
		"control name":       func(r *service.OAuthClientRegistration) { r.Name = "test\n" },
		"large name":         func(r *service.OAuthClientRegistration) { r.Name = strings.Repeat("a", 201) },
		"no redirect":        func(r *service.OAuthClientRegistration) { r.RedirectURIs = nil },
		"duplicate redirect": func(r *service.OAuthClientRegistration) { r.RedirectURIs = append(r.RedirectURIs, r.RedirectURIs[0]) },
		"too many redirects": func(r *service.OAuthClientRegistration) { r.RedirectURIs = make([]string, 17) },
		"no resources":       func(r *service.OAuthClientRegistration) { r.Resources = nil },
		"duplicate resource": func(r *service.OAuthClientRegistration) { r.Resources = append(r.Resources, r.Resources[0]) },
		"no scopes":          func(r *service.OAuthClientRegistration) { r.Resources[0].Scopes = nil },
		"duplicate scopes":   func(r *service.OAuthClientRegistration) { r.Resources[0].Scopes = []string{"read", "read"} },
		"no grant":           func(r *service.OAuthClientRegistration) { r.GrantTypes = nil },
		"refresh only":       func(r *service.OAuthClientRegistration) { r.GrantTypes = []string{"refresh_token"} },
		"password grant":     func(r *service.OAuthClientRegistration) { r.GrantTypes = []string{"authorization_code", "password"} },
		"duplicate grant": func(r *service.OAuthClientRegistration) {
			r.GrantTypes = []string{"authorization_code", "authorization_code"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRegistration()
			mutate(r)
			require.ErrorIs(t, r.Validate(), service.ErrInvalidArgument)
		})
	}
	for _, raw := range []string{"/relative", "https:callback", "http://localhost/cb", "http://127.0.0.2/cb", "http://example.test/cb", "https://user@example.test/cb", "https://example.test/cb#fragment", "https://example.test/cb#", "https://*.example.test/cb", "https://example.test:0/cb", "https://example.test:65536/cb", "https://example.test:/cb", "https://example.test/\\cb", "https://example.test/cb\n", "com.example.app:/callback"} {
		t.Run("redirect "+raw, func(t *testing.T) {
			r := validRegistration()
			r.RedirectURIs = []string{raw}
			require.ErrorIs(t, r.Validate(), service.ErrInvalidArgument)
		})
	}
	for _, raw := range []string{"relative", "http://api.example.test/", "https://api.example.test/#", "urn:", "https://user@api.example.test/", "https:opaque", "https://api.example.test:/"} {
		t.Run("resource "+raw, func(t *testing.T) {
			r := validRegistration()
			r.Resources[0].Resource = raw
			require.ErrorIs(t, r.Validate(), service.ErrInvalidArgument)
		})
	}
	r := validRegistration()
	r.Resources[0].Resource = "urn:example:records"
	require.NoError(t, r.Validate())
	for _, scope := range []string{"", "two scopes", "quote\"", "back\\slash", "é", strings.Repeat("a", 129)} {
		t.Run("scope "+scope, func(t *testing.T) {
			r := validRegistration()
			r.Resources[0].Scopes = []string{scope}
			require.ErrorIs(t, r.Validate(), service.ErrInvalidArgument)
		})
	}
}

func TestOAuthClientRequestBounds(t *testing.T) {
	c := &service.OAuthClient{Kind: service.OAuthClientNativePublic, Revision: 1, Registration: *validRegistration()}
	for _, redirect := range []string{"http://127.0.0.1:54321/callback", "http://[::1]:54321/callback", "https://app.example.test/callback?mode=native"} {
		require.NoError(t, c.ValidateOAuthRequest(redirect, "https://api.example.test/", []string{"records:read"}, "authorization_code"))
	}
	for _, redirect := range []string{"http://127.0.0.1:54321/other", "http://127.0.0.1:54321/callback?", "http://127.0.0.1:54321/%63allback", "http://localhost:54321/callback", "http://[0:0:0:0:0:0:0:1]:54321/callback", "https://app.example.test:443/callback?mode=native", "https://app.example.test/callback?mode=other"} {
		require.Error(t, c.ValidateOAuthRequest(redirect, "https://api.example.test/", []string{"records:read"}, "authorization_code"))
	}
	require.Error(t, c.ValidateOAuthRequest(c.Registration.RedirectURIs[0], "https://other.example.test/", []string{"records:read"}, "authorization_code"))
	require.Error(t, c.ValidateOAuthRequest(c.Registration.RedirectURIs[0], "https://api.example.test/", []string{"admin"}, "authorization_code"))
	require.Error(t, c.ValidateOAuthRequest(c.Registration.RedirectURIs[0], "https://api.example.test/", nil, "authorization_code"))
	require.Error(t, c.ValidateOAuthRequest(c.Registration.RedirectURIs[0], "https://api.example.test/", []string{"records:read"}, "client_credentials"))
	c.Registration.Disabled = true
	require.ErrorIs(t, c.ValidateOAuthRequest(c.Registration.RedirectURIs[0], "https://api.example.test/", []string{"records:read"}, "authorization_code"), service.ErrPermissionDenied)
	require.ErrorIs(t, (*service.OAuthClient)(nil).ValidateOAuthRequest("", "", nil, ""), service.ErrPermissionDenied)
}

func TestOAuthClientManagementAuthorizationAndRevision(t *testing.T) {
	ctx := context.Background()
	repo := memory.New()
	cfg := &config.Config{}
	svc := service.NewAuthService(repo, cfg, nil, nil, audit.NewLogger(nil, "", zap.NewNop()), nil, []byte(strings.Repeat("p", 32)), nil, nil, zap.NewNop())
	for _, tc := range []struct {
		name, role, status, kind string
		anonymous                bool
		allowed                  bool
	}{
		{name: "admin", role: "admin", status: "active", allowed: true},
		{name: "owner is not project admin", role: "owner", status: "active"},
		{name: "member", role: "member", status: "active"},
		{name: "suspended", role: "admin", status: "suspended"},
		{name: "agent", role: "admin", status: "active", kind: service.UserKindAgent},
		{name: "anonymous", role: "admin", status: "active", anonymous: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := repo.CreateUser(ctx, &service.User{Email: tc.name + "@example.test", Role: tc.role, Status: tc.status, Kind: tc.kind, IsAnonymous: tc.anonymous, OwnerUserID: func() string {
				if tc.kind == service.UserKindAgent {
					return "owner"
				}
				return ""
			}()})
			require.NoError(t, err)
			client, err := svc.CreateOAuthClient(ctx, id, validRegistration())
			if !tc.allowed {
				require.ErrorIs(t, err, service.ErrPermissionDenied)
				_, err = svc.GetOAuthClient(ctx, id, "unknown")
				require.ErrorIs(t, err, service.ErrPermissionDenied)
				_, err = svc.UpdateOAuthClient(ctx, id, "unknown", 1, validRegistration())
				require.ErrorIs(t, err, service.ErrPermissionDenied)
				_, err = svc.ListOAuthClients(ctx, id, "", 10)
				require.ErrorIs(t, err, service.ErrPermissionDenied)
				return
			}
			require.NoError(t, err)
			require.EqualValues(t, 1, client.Revision)
			got, err := svc.GetOAuthClient(ctx, id, client.ID)
			require.NoError(t, err)
			require.Equal(t, client, got)
			next := validRegistration()
			next.Disabled = true
			updated, err := svc.UpdateOAuthClient(ctx, id, client.ID, 1, next)
			require.NoError(t, err)
			require.EqualValues(t, 2, updated.Revision)
			require.True(t, updated.Registration.Disabled)
			_, err = svc.UpdateOAuthClient(ctx, id, client.ID, 1, validRegistration())
			require.ErrorIs(t, err, service.ErrOAuthClientRevision)
			next.Disabled = false
			enabled, err := svc.UpdateOAuthClient(ctx, id, client.ID, 2, next)
			require.NoError(t, err)
			require.EqualValues(t, 3, enabled.Revision)
			require.True(t, updated.Registration.Disabled, "previous snapshot never mutates")
			list, err := svc.ListOAuthClients(ctx, id, "", 0)
			require.NoError(t, err)
			require.Len(t, list, 1)
			_, err = svc.UpdateOAuthClient(ctx, id, client.ID, math.MaxInt64, next)
			require.ErrorIs(t, err, service.ErrInvalidArgument)
			_, err = svc.GetOAuthClient(ctx, id, "absent")
			require.ErrorIs(t, err, service.ErrNotFound)
			other := service.WithProjectScope(ctx, &service.ProjectScope{ProjectID: "another-project"})
			_, err = svc.GetOAuthClient(other, id, client.ID)
			require.ErrorIs(t, err, service.ErrPermissionDenied)
		})
	}
	_, err := svc.CreateOAuthClient(ctx, "", nil)
	require.ErrorIs(t, err, service.ErrUnauthenticated)
	_, err = svc.CreateOAuthClient(ctx, "unknown", validRegistration())
	require.ErrorIs(t, err, service.ErrPermissionDenied)
	if !errors.Is(service.ValidateOAuthClientPage("", -1), service.ErrInvalidArgument) {
		t.Fatal("invalid page accepted")
	}
}
