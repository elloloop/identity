package identityserver

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type guardianPolicyProject struct{ project *service.AdminProject }

func (p guardianPolicyProject) ActiveProjectByID(_ context.Context, id string) (*service.AdminProject, error) {
	if p.project.ID != id {
		return nil, nil
	}
	return p.project, nil
}

func TestGuardianPolicy_DefaultHTTPAndNativeGRPCCannotBypass(t *testing.T) {
	cfg := config.Load()
	cfg.RepoDriver = "memory"
	cfg.DefaultProjectID = "strict-default"
	cfg.DefaultProjectAccessMode = "open"
	cfg.AgeGateEnabled = true
	cfg.AgeGateChildMaxAge = 12
	cfg.AgeGateAdultAge = 18
	cfg.GuardianStepUpAllowNoPassword = true
	repo := memory.New()
	signer := jwttest.NewSigner(t, "guardian-policy")
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Example", Origin: "http://localhost:9002"})
	if err != nil {
		t.Fatal(err)
	}
	project := &service.AdminProject{ID: cfg.DefaultProjectID, Guardian: service.ProjectGuardianConfig{RequireStepUp: true, RequireAdultProfile: true}}
	built, err := app.New(app.Deps{Config: cfg, Logger: zap.NewNop(), Signer: signer, Repo: repo, DB: repo, Passkeys: pk, TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"), ActiveProjects: guardianPolicyProject{project: project}})
	if err != nil {
		t.Fatal(err)
	}
	scoped := repo.WithProject(cfg.DefaultProjectID)
	ctx := context.Background()
	parent, err := scoped.CreateUser(ctx, &service.User{Email: "parent@example.test", Status: service.StatusActive, Kind: service.UserKindPerson, DateOfBirthMs: time.Now().AddDate(-35, 0, 0).UnixMilli(), PhoneVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	req := &identitypb.CreateManagedChildAccountRequest{Username: "kid.one", DateOfBirthMs: time.Now().AddDate(-8, 0, 0).UnixMilli(), Password: "Strong-child-password-42!", PolicyVersion: "policy-v1"}
	bridge := newGRPCBridge(built, zap.NewNop(), grpcTrust{})
	nativeCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("x-authenticated-user-id", parent))
	if _, err := bridge.CreateManagedChildAccount(nativeCtx, req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("native passwordless bypass: %v", err)
	}
	server := httptest.NewServer(built.Handler)
	t.Cleanup(server.Close)
	token, err := signer.SignAccessToken(ctx, jwt.Claims{Sub: parent, Project: cfg.DefaultProjectID, Tenant: cfg.DefaultTenantID, Role: service.RoleMember}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	call := connect.NewRequest(req)
	call.Header().Set("Authorization", "Bearer "+token)
	client := identityconnect.NewIdentityServiceClient(server.Client(), server.URL)
	if _, err := client.CreateManagedChildAccount(ctx, call); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("HTTP default pin bypass: %v", err)
	}
	if child, err := scoped.FindUserByUsername(ctx, req.Username); err != nil || child != nil {
		t.Fatal("child created before fresh proof")
	}
}
