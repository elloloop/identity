package identityserver_test

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/identityserver"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
)

// newTestServer builds a Server backed by an in-memory repository and a
// test signer, so the mount tests run with no external datastore, file
// signer, or OTel exporter. Workers are started and drained via t.Cleanup.
func newTestServer(t *testing.T) *identityserver.Server {
	t.Helper()

	repo := memory.New()
	cfg := config.Config{ // #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
		DefaultTenantID:               "tenant",
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		AllowedOrigins:                "http://localhost:9002",
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "MountTest",
		PasskeyOrigin:                 "http://localhost:9002",
		PasskeyChallengeExpirySeconds: 300,
		QRLoginBaseURL:                "http://localhost:9002",
		QRLoginExpirySeconds:          300,
		TOTPIssuer:                    "MountTest",
		PasswordResetExpirySeconds:    3600,
	}

	srv, err := identityserver.New(context.Background(), identityserver.Options{
		Config: cfg,
		Signer: jwttest.NewSigner(t, "mount-test"),
		Repo:   repo,
		DB:     repo,
	})
	if err != nil {
		t.Fatalf("identityserver.New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return srv
}

// TestHandlerMount exercises the http.Handler surface: mount Handler on a
// test HTTP server and drive a Connect RPC through it end to end.
func TestHandlerMount(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t)

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	client := identityconnectgen.NewIdentityServiceClient(httpSrv.Client(), httpSrv.URL)
	resp, err := client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "handler-mount@example.com",
		Password: "Password-12345678a",
	}))
	if err != nil {
		t.Fatalf("PasswordSignup over http.Handler: %v", err)
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "handler-mount@example.com" {
		t.Fatalf("email = %q; want handler-mount@example.com", got)
	}
	if resp.Msg.GetAccessToken() == "" {
		t.Fatalf("expected an access token, got empty")
	}
}

// TestRegisterGRPCMount exercises the native gRPC surface: register
// identity onto a real *grpc.Server, then drive an RPC through a grpc-go
// client. This proves the grpc_bridge delegates to the same service layer
// the Connect handler uses.
func TestRegisterGRPCMount(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	srv.RegisterGRPC(grpcSrv)

	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcSrv.Serve(lis) }()
	t.Cleanup(func() {
		grpcSrv.GracefulStop()
		if err := <-serveErr; err != nil {
			t.Errorf("grpc Serve: %v", err)
		}
	})

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := identitypb.NewIdentityServiceClient(conn)
	resp, err := client.PasswordSignup(context.Background(), &identitypb.PasswordSignupRequest{
		Email:    "grpc-mount@example.com",
		Password: "Password-12345678a",
	})
	if err != nil {
		t.Fatalf("PasswordSignup over *grpc.Server: %v", err)
	}
	if got := resp.GetUser().GetEmail(); got != "grpc-mount@example.com" {
		t.Fatalf("email = %q; want grpc-mount@example.com", got)
	}
	if resp.GetAccessToken() == "" {
		t.Fatalf("expected an access token, got empty")
	}

	// The gRPC bridge copies incoming metadata into the Connect request
	// headers, so an authed RPC works when the host supplies the
	// authenticated user id (the documented native-gRPC auth contract:
	// the HTTP JWT middleware is bypassed, so the host's interceptor must
	// populate it). Drive GetCurrentUser for the user just created.
	authCtx := metadata.NewOutgoingContext(context.Background(),
		metadata.Pairs("x-authenticated-user-id", resp.GetUser().GetId()))
	cur, err := client.GetCurrentUser(authCtx, &identitypb.GetCurrentUserRequest{})
	if err != nil {
		t.Fatalf("GetCurrentUser over *grpc.Server: %v", err)
	}
	if got := cur.GetUser().GetEmail(); got != "grpc-mount@example.com" {
		t.Fatalf("GetCurrentUser email = %q; want grpc-mount@example.com", got)
	}
}
