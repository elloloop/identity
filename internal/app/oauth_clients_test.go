package app

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestOAuthClientRegistryServedChain(t *testing.T) {
	ctx := context.Background()
	cfg := newTestConfig()
	cfg.DefaultProjectID = config.DefaultProjectIDFallback
	repo := memory.New()
	scoped := repo.WithProject(cfg.DefaultProjectID)
	signer := jwttest.NewSigner(t, "oauth-registry-test")
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Identity test", Origin: "http://localhost:9002"})
	require.NoError(t, err)
	built, err := New(Deps{Config: cfg, Logger: zap.NewNop(), Signer: signer, Repo: repo, DB: repo, Passkeys: pk, TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH")})
	require.NoError(t, err)
	server := httptest.NewServer(built.Handler)
	t.Cleanup(server.Close)
	client := identityconnect.NewIdentityServiceClient(server.Client(), server.URL)
	adminID, err := scoped.CreateUser(ctx, &service.User{Email: "admin@example.test", Role: "admin", Status: "active"})
	require.NoError(t, err)
	adminToken, err := signer.SignAccessToken(ctx, jwt.Claims{Sub: adminID, Role: "admin", Tenant: cfg.DefaultTenantID, Project: cfg.DefaultProjectID}, time.Minute)
	require.NoError(t, err)
	registration := &identitypb.OAuthClientRegistration{Name: "Acme desktop", RedirectUris: []string{"http://127.0.0.1/callback"}, Resources: []*identitypb.OAuthResourceBounds{{Resource: "urn:example:records", Scopes: []string{"read"}}}, GrantTypes: []string{"authorization_code"}}
	req := connect.NewRequest(&identitypb.CreateOAuthClientRequest{Registration: registration})
	req.Header().Set("Authorization", "Bearer "+adminToken)
	created, err := client.CreateOAuthClient(ctx, req)
	require.NoError(t, err)
	require.EqualValues(t, 1, created.Msg.Client.Revision)
	require.Equal(t, identitypb.OAuthClientKind_O_AUTH_CLIENT_KIND_NATIVE_PUBLIC, created.Msg.Client.Kind)
	id := created.Msg.Client.ClientId
	get := connect.NewRequest(&identitypb.GetOAuthClientRequest{ClientId: id})
	get.Header().Set("Authorization", "Bearer "+adminToken)
	got, err := client.GetOAuthClient(ctx, get)
	require.NoError(t, err)
	require.Equal(t, "Acme desktop", got.Msg.Client.Registration.Name)
	registration.Disabled = true
	update := connect.NewRequest(&identitypb.UpdateOAuthClientRequest{ClientId: id, ExpectedRevision: 1, Registration: registration})
	update.Header().Set("Authorization", "Bearer "+adminToken)
	updated, err := client.UpdateOAuthClient(ctx, update)
	require.NoError(t, err)
	require.EqualValues(t, 2, updated.Msg.Client.Revision)
	require.True(t, updated.Msg.Client.Registration.Disabled)
	_, err = client.UpdateOAuthClient(ctx, update)
	require.Equal(t, connect.CodeAborted, connect.CodeOf(err))
	list := connect.NewRequest(&identitypb.ListOAuthClientsRequest{})
	list.Header().Set("Authorization", "Bearer "+adminToken)
	listed, err := client.ListOAuthClients(ctx, list)
	require.NoError(t, err)
	require.Len(t, listed.Msg.Clients, 1)

	calls := []struct {
		name string
		call func(string, string) error
	}{
		{"Create", func(token, spoof string) error {
			r := connect.NewRequest(&identitypb.CreateOAuthClientRequest{Registration: registration})
			r.Header().Set("Authorization", token)
			r.Header().Set("X-Authenticated-User-Id", spoof)
			_, err := client.CreateOAuthClient(ctx, r)
			return err
		}},
		{"Get", func(token, spoof string) error {
			r := connect.NewRequest(&identitypb.GetOAuthClientRequest{ClientId: id})
			r.Header().Set("Authorization", token)
			r.Header().Set("X-Authenticated-User-Id", spoof)
			_, err := client.GetOAuthClient(ctx, r)
			return err
		}},
		{"Update", func(token, spoof string) error {
			r := connect.NewRequest(&identitypb.UpdateOAuthClientRequest{ClientId: id, ExpectedRevision: 2, Registration: registration})
			r.Header().Set("Authorization", token)
			r.Header().Set("X-Authenticated-User-Id", spoof)
			_, err := client.UpdateOAuthClient(ctx, r)
			return err
		}},
		{"List", func(token, spoof string) error {
			r := connect.NewRequest(&identitypb.ListOAuthClientsRequest{})
			r.Header().Set("Authorization", token)
			r.Header().Set("X-Authenticated-User-Id", spoof)
			_, err := client.ListOAuthClients(ctx, r)
			return err
		}},
	}
	memberID, err := scoped.CreateUser(ctx, &service.User{Email: "member@example.test", Role: "member", Status: "active"})
	require.NoError(t, err)
	memberToken, err := signer.SignAccessToken(ctx, jwt.Claims{Sub: memberID, Role: "admin", Tenant: cfg.DefaultTenantID, Project: cfg.DefaultProjectID}, time.Minute)
	require.NoError(t, err)
	agentID, err := scoped.CreateUser(ctx, &service.User{Email: "agent@example.test", Role: "admin", Status: "active", Kind: service.UserKindAgent, OwnerUserID: adminID})
	require.NoError(t, err)
	agentToken, err := signer.SignAccessToken(ctx, jwt.Claims{Sub: agentID, Role: "admin", Kind: "agent", Tenant: cfg.DefaultTenantID, Project: cfg.DefaultProjectID}, time.Minute)
	require.NoError(t, err)
	for _, call := range calls {
		t.Run(call.name, func(t *testing.T) {
			require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(call.call("", adminID)), "spoofed trusted header must not authenticate")
			require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(call.call("Bearer "+memberToken, adminID)), "stored role decides, not token role or spoofed header")
			require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(call.call("Bearer "+agentToken, adminID)), "an agent cannot administer OAuth clients")
		})
	}
	require.NoError(t, scoped.UpdateUser(ctx, adminID, map[string]any{"status": "suspended"}))
	_, err = client.ListOAuthClients(ctx, list)
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "suspension is effective with an existing signed token: %v", err)
}
