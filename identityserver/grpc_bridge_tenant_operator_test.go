package identityserver_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
)

// The tenant-operator budget holds on native gRPC too, and is the HTTP
// surface's: a call that presents a tenant_operator key spends it whichever
// transport carries it, and a call without one never does.
func TestRegisterGRPC_TenantOperatorThrottled(t *testing.T) {
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
		if status.Code(err) == codes.ResourceExhausted {
			t.Fatalf("call %d without a key: %v, want it uncounted", i+1, err)
		}
	}

	withKey := metadata.AppendToOutgoingContext(context.Background(), middleware.TenantOperatorKeyHeader, key)
	if _, err := grpcClient.AdminGetTenant(withKey, &identitypb.AdminGetTenantRequest{TenantId: "t"}); status.Code(err) == codes.ResourceExhausted {
		t.Fatalf("first keyed call: %v, want it admitted to the handler", err)
	}
	req := connect.NewRequest(&identitypb.AdminListTenantsRequest{})
	req.Header().Set(middleware.TenantOperatorKeyHeader, key)
	if _, err := httpClient.AdminListTenants(context.Background(), req); connect.CodeOf(err) == connect.CodeUnavailable {
		t.Fatalf("second keyed call, over HTTP: %v, want it admitted to the handler", err)
	}
	_, err := grpcClient.GetLoginPolicy(withKey, &identitypb.GetLoginPolicyRequest{})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("third keyed call across procedures and transports: %v, want ResourceExhausted", err)
	}
	if _, err := grpcClient.AdminGetTenant(context.Background(), &identitypb.AdminGetTenantRequest{TenantId: "t"}); status.Code(err) == codes.ResourceExhausted {
		t.Fatalf("a call without a key after the budget is spent: %v, want it uncounted", err)
	}
}
