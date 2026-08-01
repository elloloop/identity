package identityserver_test

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/identityserver"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
)

// newTestServer builds a Server backed by an in-memory repository and a
// test signer, so the mount tests run with no external datastore, file
// signer, or OTel exporter. Workers are started and drained via t.Cleanup.
func newTestServer(t *testing.T) *identityserver.Server {
	t.Helper()
	return newTestServerWith(t, nil, nil)
}

// newTestServerWith builds the mount fixture with optional config
// mutation and option decoration, for tests that exercise a config-gated
// surface (client assurance).
func newTestServerWith(t *testing.T, mutate func(*config.Config), decorate func(*identityserver.Options)) *identityserver.Server {
	t.Helper()

	repo := memory.New()
	cfg := config.Config{ // #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
		DefaultTenantID: "tenant",
		// Open the env default project so this mount test drives the handler chain,
		// not the access gate (default-DENY requires an explicit mode).
		DefaultProjectAccessMode:      "open",
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

	if mutate != nil {
		mutate(&cfg)
	}
	opts := identityserver.Options{
		Config: cfg,
		Signer: jwttest.NewSigner(t, "mount-test"),
		Repo:   repo,
		DB:     repo,
	}
	if decorate != nil {
		decorate(&opts)
	}

	srv, err := identityserver.New(context.Background(), opts)
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

// stubAssuranceVerifier accepts one captcha value, standing in for
// Turnstile on the native-gRPC surface.
type stubAssuranceVerifier struct{}

func (stubAssuranceVerifier) Name() string { return "stub" }
func (stubAssuranceVerifier) Verify(_ context.Context, token, _ string) error {
	if token == "ok" {
		return nil
	}
	return assurance.ErrVerificationFailed
}

// TestRegisterGRPCAssuranceParity pins that the client-assurance RPCs are
// reachable over the native gRPC surface. Enforcement reads the
// X-Assurance-Token header, so a host whose bridge omits the exchange
// RPCs would have every gated RPC deny forever with no way to obtain a
// token — the v3 CAPTCHA solution used to ride inside the request message,
// so this parity is new and load-bearing.
func TestRegisterGRPCAssuranceParity(t *testing.T) {
	t.Parallel()

	srv := newTestServerWith(t, func(c *config.Config) {
		c.AssuranceEnabled = true
		c.AssuranceChallengeTTLSeconds = 300
		c.AssuranceTokenTTLSeconds = 3600
		c.AssuranceWebProvider = config.AssuranceWebProviderTurnstile
		c.AssuranceTurnstileSecret = "secret"
		c.AssuranceTurnstileSiteKey = "sitekey"
		// A real iOS arm, so a REACHED RefreshAssuranceToken handler rejects
		// the bogus assertion with PermissionDenied. Without it the handler
		// would answer Unimplemented — indistinguishable from an unbridged
		// method, which would make the parity assertion vacuous.
		c.AssuranceIOSTeamID = "TEAM123456"
		c.AssuranceIOSBundleID = "com.example.app"
		c.AssuranceEnforcePasswordSignup = true
	}, func(o *identityserver.Options) {
		o.AssuranceWebVerifier = stubAssuranceVerifier{}
	})

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
	ctx := context.Background()

	// Without a token the gated RPC denies.
	if _, err := client.PasswordSignup(ctx, &identitypb.PasswordSignupRequest{
		Email: "grpc-assured@example.com", Password: "Password-12345678a",
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unassured signup code = %v, want PermissionDenied", status.Code(err))
	}

	// The exchange must be reachable over gRPC — this is what the missing
	// bridge methods made impossible.
	issued, err := client.IssueAssuranceToken(ctx, &identitypb.IssueAssuranceTokenRequest{
		Platform: "web", WebToken: "ok",
	})
	if err != nil {
		t.Fatalf("IssueAssuranceToken over *grpc.Server: %v", err)
	}
	if issued.GetAssuranceToken() == "" {
		t.Fatal("no assurance token returned")
	}

	// The challenge RPC is bridged too (mobile clients start here).
	ch, err := client.CreateAssuranceChallenge(ctx, &identitypb.CreateAssuranceChallengeRequest{
		Platform: "ios",
	})
	if err != nil {
		t.Fatalf("CreateAssuranceChallenge over *grpc.Server: %v", err)
	}

	// The refresh RPC must be bridged too: it is the only wire path to the
	// App Attest assertion + sign-counter CAS, so an unbridged method would
	// leave iOS clients unable to renew without a full re-attestation. This
	// deployment configures no App Attest verifier, so Unimplemented is the
	// expected verdict — what matters is that the call REACHES the handler
	// rather than hitting the bridge's UnimplementedIdentityServiceServer.
	_, err = client.RefreshAssuranceToken(ctx, &identitypb.RefreshAssuranceTokenRequest{
		ChallengeId: ch.GetChallengeId(),
		KeyId:       "dW5rbm93bi1rZXk",
		Assertion:   []byte("assertion"),
	})
	// PermissionDenied means the handler ran and rejected the evidence.
	// Unimplemented here would mean the bridge method is missing entirely.
	if code := status.Code(err); code != codes.PermissionDenied {
		t.Fatalf("RefreshAssuranceToken over *grpc.Server: code = %v, want PermissionDenied "+
			"(Unimplemented means the bridge method is missing) (err=%v)", code, err)
	}

	// Metadata carries the token into the Connect handler, so the gated RPC
	// now succeeds.
	assuredCtx := metadata.NewOutgoingContext(ctx,
		metadata.Pairs(assurance.HeaderName, issued.GetAssuranceToken()))
	resp, err := client.PasswordSignup(assuredCtx, &identitypb.PasswordSignupRequest{
		Email: "grpc-assured@example.com", Password: "Password-12345678a",
	})
	if err != nil {
		t.Fatalf("assured signup over *grpc.Server: %v", err)
	}
	if resp.GetAccessToken() == "" {
		t.Fatal("expected an access token")
	}
}
