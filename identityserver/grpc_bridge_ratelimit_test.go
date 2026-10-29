package identityserver_test

import (
	"context"
	"net"
	"net/http/httptest"
	"strconv"
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
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
)

// serveGRPC registers srv on a loopback *grpc.Server and returns a client.
func serveGRPC(t *testing.T, srv *identityserver.Server) identitypb.IdentityServiceClient {
	t.Helper()
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
	return identitypb.NewIdentityServiceClient(conn)
}

func lookupRequest() *identitypb.LookupUsersRequest {
	return &identitypb.LookupUsersRequest{Emails: []string{"a@example.com"}}
}

// The memory driver has no control plane, so an admitted LookupUsers is
// UNIMPLEMENTED; the throttle runs before the handler, so an over-quota call
// is RESOURCE_EXHAUSTED instead, carrying the configured window as its
// retry-after — the gRPC counterpart of the HTTP 429.
func TestRegisterGRPC_LookupUsersThrottled(t *testing.T) {
	t.Parallel()
	srv := newTestServerWith(t, func(c *config.Config) {
		c.RateLimitDirectoryPerIP = 2
		c.RateLimitWindowSeconds = 45
	}, nil)
	client := serveGRPC(t, srv)

	for i := range 2 {
		// A client cannot buy a fresh budget by claiming another address:
		// its peer is not a trusted proxy, so x-forwarded-for is ignored.
		ctx := metadata.AppendToOutgoingContext(context.Background(), "x-forwarded-for", "198.51.100."+strconv.Itoa(i+1))
		_, err := client.LookupUsers(ctx, lookupRequest())
		if got := status.Code(err); got != codes.Unimplemented {
			t.Fatalf("call %d: code = %v (%v), want Unimplemented from the handler", i+1, got, err)
		}
	}

	var header metadata.MD
	_, err := client.LookupUsers(context.Background(), lookupRequest(), grpc.Header(&header))
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("over quota: code = %v (%v), want ResourceExhausted", got, err)
	}
	if got := header.Get("retry-after"); len(got) != 1 || got[0] != "45" {
		t.Fatalf("retry-after = %v, want [45]", got)
	}

	// The limit is LookupUsers' alone: other RPCs on the bridge are untouched.
	if _, err := client.PasswordSignup(context.Background(), &identitypb.PasswordSignupRequest{
		Email: "after-throttle@example.com", Password: "Password-12345678a",
	}); err != nil {
		t.Fatalf("PasswordSignup after the directory throttle: %v", err)
	}
}

// HTTP and native gRPC draw on one directory budget per client IP: calls on
// either surface count against the same limiter, so serving both does not
// double what one caller may spend.
func TestRegisterGRPC_LookupUsersSharesHTTPBudget(t *testing.T) {
	t.Parallel()
	srv := newTestServerWith(t, func(c *config.Config) {
		c.RateLimitDirectoryPerIP = 2
	}, nil)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	httpClient := identityconnectgen.NewIdentityServiceClient(httpSrv.Client(), httpSrv.URL)
	grpcClient := serveGRPC(t, srv)

	if _, err := httpClient.LookupUsers(context.Background(), connect.NewRequest(lookupRequest())); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("HTTP call: %v, want Unimplemented from the handler", err)
	}
	if _, err := grpcClient.LookupUsers(context.Background(), lookupRequest()); status.Code(err) != codes.Unimplemented {
		t.Fatalf("gRPC call: %v, want Unimplemented from the handler", err)
	}
	_, err := grpcClient.LookupUsers(context.Background(), lookupRequest())
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("third call across surfaces: %v, want ResourceExhausted", err)
	}
	_, err = httpClient.LookupUsers(context.Background(), connect.NewRequest(lookupRequest()))
	// The HTTP surface answers 429 before Connect runs, which a Connect
	// client reports as UNAVAILABLE.
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("HTTP call after the gRPC calls spent the budget: %v, want the 429 (Unavailable)", err)
	}
}

// tenantOperatorCalls calls each tenant operation over native gRPC, keyed by
// its procedure, so a test can drive every one app.TenantOperatorProcedures
// names.
var tenantOperatorCalls = map[string]func(ctx context.Context, c identitypb.IdentityServiceClient) error{
	identityconnectgen.IdentityServiceAdminGetTenantProcedure: func(ctx context.Context, c identitypb.IdentityServiceClient) error {
		_, err := c.AdminGetTenant(ctx, &identitypb.AdminGetTenantRequest{TenantId: "t"})
		return err
	},
	identityconnectgen.IdentityServiceAdminListTenantsProcedure: func(ctx context.Context, c identitypb.IdentityServiceClient) error {
		_, err := c.AdminListTenants(ctx, &identitypb.AdminListTenantsRequest{})
		return err
	},
	identityconnectgen.IdentityServiceAdminSuspendTenantProcedure: func(ctx context.Context, c identitypb.IdentityServiceClient) error {
		_, err := c.AdminSuspendTenant(ctx, &identitypb.AdminSuspendTenantRequest{TenantId: "t"})
		return err
	},
	identityconnectgen.IdentityServiceAdminRestoreTenantProcedure: func(ctx context.Context, c identitypb.IdentityServiceClient) error {
		_, err := c.AdminRestoreTenant(ctx, &identitypb.AdminRestoreTenantRequest{TenantId: "t"})
		return err
	},
	identityconnectgen.IdentityServiceAdminRecoverTenantOwnershipProcedure: func(ctx context.Context, c identitypb.IdentityServiceClient) error {
		_, err := c.AdminRecoverTenantOwnership(ctx, &identitypb.AdminRecoverTenantOwnershipRequest{TenantId: "t"})
		return err
	},
	identityconnectgen.IdentityServiceGetLoginPolicyProcedure: func(ctx context.Context, c identitypb.IdentityServiceClient) error {
		_, err := c.GetLoginPolicy(ctx, &identitypb.GetLoginPolicyRequest{})
		return err
	},
}

// Every tenant operation spends the tenant-operator budget on native gRPC
// when it presents a key, because the bridge throttles each one by hand
// (the HTTP middleware does not run there). A seventh procedure added to
// app.TenantOperatorProcedures fails this test until it has a case here.
func TestRegisterGRPC_EveryTenantOperationThrottled(t *testing.T) {
	t.Parallel()
	if len(tenantOperatorCalls) != len(app.TenantOperatorProcedures) {
		t.Fatalf("%d calls for %d tenant operator procedures", len(tenantOperatorCalls), len(app.TenantOperatorProcedures))
	}
	for _, procedure := range app.TenantOperatorProcedures {
		call, ok := tenantOperatorCalls[procedure]
		if !ok {
			t.Fatalf("no gRPC call for tenant operator procedure %s", procedure)
		}
		t.Run(procedure, func(t *testing.T) {
			t.Parallel()
			srv := newTestServerWith(t, func(c *config.Config) {
				c.RateLimitDirectoryPerIP = 1
				c.RateLimitWindowSeconds = 45
			}, nil)
			client := serveGRPC(t, srv)

			// Without a key the call is not counted, however often it is made.
			for i := range 2 {
				if got := status.Code(call(context.Background(), client)); got != codes.Unimplemented {
					t.Fatalf("call %d without a key: code = %v, want Unimplemented from the handler", i+1, got)
				}
			}
			withKey := metadata.AppendToOutgoingContext(context.Background(), middleware.TenantOperatorKeyHeader, "ok_unknown.secret")
			if got := status.Code(call(withKey, client)); got != codes.Unimplemented {
				t.Fatalf("first keyed call: code = %v, want Unimplemented from the handler", got)
			}
			err := call(withKey, client)
			if got := status.Code(err); got != codes.ResourceExhausted {
				t.Fatalf("second keyed call: code = %v (%v), want ResourceExhausted", got, err)
			}
		})
	}
}

// The tenant-operator budget is the HTTP surface's too: a call that presents
// a tenant_operator key spends it whichever transport carries it, across
// the tenant operations, and a call without one never does.
func TestRegisterGRPC_TenantOperatorSharesHTTPBudget(t *testing.T) {
	t.Parallel()
	srv := newTestServerWith(t, func(c *config.Config) {
		c.RateLimitDirectoryPerIP = 2
	}, nil)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	httpClient := identityconnectgen.NewIdentityServiceClient(httpSrv.Client(), httpSrv.URL)
	grpcClient := serveGRPC(t, srv)

	const key = "ok_unknown.secret"
	for i := range 3 {
		_, err := grpcClient.AdminGetTenant(context.Background(), &identitypb.AdminGetTenantRequest{TenantId: "t"})
		if got := status.Code(err); got != codes.Unimplemented {
			t.Fatalf("call %d without a key: code = %v, want Unimplemented from the handler", i+1, got)
		}
	}

	withKey := metadata.AppendToOutgoingContext(context.Background(), middleware.TenantOperatorKeyHeader, key)
	if _, err := grpcClient.AdminGetTenant(withKey, &identitypb.AdminGetTenantRequest{TenantId: "t"}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("first keyed call: %v, want Unimplemented from the handler", err)
	}
	req := connect.NewRequest(&identitypb.AdminListTenantsRequest{})
	req.Header().Set(middleware.TenantOperatorKeyHeader, key)
	if _, err := httpClient.AdminListTenants(context.Background(), req); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("second keyed call, over HTTP: %v, want Unimplemented from the handler", err)
	}
	if _, err := grpcClient.GetLoginPolicy(withKey, &identitypb.GetLoginPolicyRequest{}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("third keyed call across procedures and transports: %v, want ResourceExhausted", err)
	}
	if _, err := grpcClient.AdminGetTenant(context.Background(), &identitypb.AdminGetTenantRequest{TenantId: "t"}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("a call without a key after the budget is spent: %v, want Unimplemented from the handler", err)
	}
}
