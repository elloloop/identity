package identityserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const (
	nativeChildProject = "native-child-project"
	nativeChildKey     = "ck_native.fixture-secret"
)

type nativeChildProjects struct{}

func (nativeChildProjects) ResolveByCredential(_ context.Context, key string) (*service.ResolvedProject, error) {
	switch key {
	case "pk_native":
		return &service.ResolvedProject{ID: nativeChildProject}, nil
	case "pk_other":
		return &service.ResolvedProject{ID: "other-project"}, nil
	case "pk_error":
		return nil, errors.New("fixture unavailable")
	case "pk_empty":
		return &service.ResolvedProject{}, nil
	default:
		return nil, nil
	}
}

func (nativeChildProjects) ResolveByHostname(context.Context, string) (*service.ResolvedProject, error) {
	return nil, nil
}

type nativeChildCredential struct{}

func (nativeChildCredential) CredentialByPublicIDInActiveProject(_ context.Context, id string) (*service.AdminProjectCredential, error) {
	if id != "ck_native" {
		return nil, nil
	}
	sum := sha256.Sum256([]byte("fixture-secret"))
	return &service.AdminProjectCredential{ID: "native-credential", ProjectID: nativeChildProject, Kind: service.CredentialKindManagedChildReader, PublicID: id, SecretHash: hex.EncodeToString(sum[:])}, nil
}

func nativeChildFixture(t *testing.T) (identitypb.IdentityServiceClient, service.Repository, *identitypb.GetManagedChildAuthorizationRequest) {
	t.Helper()
	cfg := config.Load()
	cfg.RepoDriver = "memory"
	cfg.DefaultProjectID = nativeChildProject
	cfg.AgeGateEnabled = true
	cfg.AgeGateChildMaxAge = 12
	cfg.AgeGateAdultAge = 18
	repo := memory.New()
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Example", Origin: "http://localhost:9002"})
	if err != nil {
		t.Fatal(err)
	}
	built, err := app.New(app.Deps{Config: cfg, Logger: zap.NewNop(), Signer: jwttest.NewSigner(t, "native-child"), Repo: repo, DB: repo, Passkeys: pk, TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"), ProjectResolver: nativeChildProjects{}, DirectoryCredentials: nativeChildCredential{}})
	if err != nil {
		t.Fatal(err)
	}
	scoped := repo.WithProject(nativeChildProject)
	child, err := scoped.CreateUser(context.Background(), &service.User{Username: "child", Kind: service.UserKindPerson, Status: service.StatusActive, DateOfBirthMs: time.Now().AddDate(-8, 0, 0).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	guardian, err := scoped.CreateUser(context.Background(), &service.User{Email: "guardian@example.test", Kind: service.UserKindPerson, Status: service.StatusActive, DateOfBirthMs: time.Now().AddDate(-35, 0, 0).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	if err := scoped.UpsertGuardianEdge(context.Background(), &service.GuardianEdge{ChildUserID: child, GuardianUserID: guardian}); err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	identitypb.RegisterIdentityServiceServer(server, newGRPCBridge(built, zap.NewNop(), grpcTrust{}))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	t.Cleanup(func() { _ = listener.Close() })
	conn, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return identitypb.NewIdentityServiceClient(conn), scoped, &identitypb.GetManagedChildAuthorizationRequest{ChildUserId: child, GuardianUserId: guardian}
}

func TestManagedChildAuthorization_NativeGRPCLiveProof(t *testing.T) {
	client, repo, req := nativeChildFixture(t)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-project-key", "pk_native", "x-managed-child-key", nativeChildKey))
	proof, err := client.GetManagedChildAuthorization(ctx, req)
	if err != nil || !proof.GetAuthorized() {
		t.Fatalf("valid native proof: %v %v", proof, err)
	}
	if err := repo.DeleteGuardianEdge(context.Background(), req.GuardianUserId, req.ChildUserId); err != nil {
		t.Fatal(err)
	}
	proof, err = client.GetManagedChildAuthorization(ctx, req)
	if err != nil || proof.GetAuthorized() {
		t.Fatalf("revoked native proof: %v %v", proof, err)
	}
}

func TestManagedChildAuthorization_NativeGRPCProjectDenials(t *testing.T) {
	client, _, req := nativeChildFixture(t)
	for _, test := range []struct {
		name, key string
		code      codes.Code
	}{
		{"missing", "", codes.Unauthenticated}, {"invalid", "pk_missing", codes.Unauthenticated}, {"empty project", "pk_empty", codes.Unauthenticated}, {"other project", "pk_other", codes.Unauthenticated}, {"unavailable", "pk_error", codes.Unavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-project-key", test.key, "x-managed-child-key", nativeChildKey))
			if _, err := client.GetManagedChildAuthorization(ctx, req); status.Code(err) != test.code {
				t.Fatalf("code=%v want=%v (%v)", status.Code(err), test.code, err)
			}
		})
	}
}
