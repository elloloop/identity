package identityserver

import (
	"context"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

const restrictedEmailProject = "restricted-email"

type emailPolicyProjects struct{ defaultID string }

func (p emailPolicyProjects) ActiveProjectByID(_ context.Context, id string) (*service.AdminProject, error) {
	switch id {
	case p.defaultID:
		return &service.AdminProject{ID: id}, nil
	case restrictedEmailProject:
		return &service.AdminProject{ID: id, EmailDelivery: service.ProjectEmailDeliveryConfig{Disabled: true}}, nil
	default:
		return nil, nil
	}
}

func (emailPolicyProjects) ResolveByCredential(_ context.Context, key string) (*service.ResolvedProject, error) {
	if key != "public-test-key" {
		return nil, nil
	}
	// Routing may still hold an older snapshot when the policy changes.
	return &service.ResolvedProject{ID: restrictedEmailProject}, nil
}

func (emailPolicyProjects) ResolveByHostname(context.Context, string) (*service.ResolvedProject, error) {
	return nil, nil
}

func TestProjectEmailDeliveryDiscovery(t *testing.T) {
	cfg := config.Load()
	cfg.RepoDriver = "memory"
	cfg.DefaultProjectID = "ordinary-email"
	cfg.RateLimitVerifyPerIP = 3
	projects := emailPolicyProjects{defaultID: cfg.DefaultProjectID}
	repo := memory.New()
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Example", Origin: "http://localhost:9002"})
	require.NoError(t, err)
	built, err := app.New(app.Deps{
		Config: cfg, Logger: zap.NewNop(), Signer: jwttest.NewSigner(t, "email-policy"), Repo: repo, DB: repo, Passkeys: pk,
		TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		ProjectResolver: projects, ActiveProjects: projects,
	})
	require.NoError(t, err)
	server := httptest.NewServer(built.Handler)
	t.Cleanup(server.Close)
	client := identityconnect.NewIdentityServiceClient(server.Client(), server.URL)
	ctx := context.Background()
	response, err := client.GetProjectEmailDelivery(ctx, connect.NewRequest(&identitypb.GetProjectEmailDeliveryRequest{}))
	require.NoError(t, err)
	require.False(t, response.Msg.Disabled)
	request := connect.NewRequest(&identitypb.GetProjectEmailDeliveryRequest{})
	request.Header().Set(middleware.ProjectKeyHeader, "public-test-key")
	response, err = client.GetProjectEmailDelivery(ctx, request)
	require.NoError(t, err)
	require.True(t, response.Msg.Disabled)
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	invalid := connect.NewRequest(&identitypb.GetProjectEmailDeliveryRequest{})
	invalid.Header().Set(middleware.ProjectKeyHeader, "invalid")
	_, err = client.GetProjectEmailDelivery(ctx, invalid)
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

	bridge := newGRPCBridge(built, zap.NewNop(), grpcTrust{})
	nativeCtx := service.WithProjectScope(ctx, &service.ProjectScope{ProjectID: restrictedEmailProject})
	native, err := bridge.GetProjectEmailDelivery(nativeCtx, &identitypb.GetProjectEmailDeliveryRequest{})
	require.NoError(t, err)
	require.True(t, native.Disabled)
	missing := service.WithProjectScope(ctx, &service.ProjectScope{ProjectID: "missing"})
	_, err = bridge.GetProjectEmailDelivery(missing, &identitypb.GetProjectEmailDeliveryRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))
}
