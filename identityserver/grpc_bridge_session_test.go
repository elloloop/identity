package identityserver

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/middleware"
	"google.golang.org/grpc/metadata"
)

func TestDelegatedGRPCSessionMetadataRequiresExplicitHostTrust(t *testing.T) {
	for _, trustSession := range []bool{false, true} {
		for _, trustTime := range []bool{false, true} {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-authenticated-session-id", "interceptor-sid", "x-authenticated-auth-time", "1234"))
			bridge := &grpcBridge{trustSessionID: trustSession, trustAuthTime: trustTime}
			_, err := invoke(ctx, bridge, &identitypb.GetAgentAuthorizationRequest{}, func(_ context.Context, req *connect.Request[identitypb.GetAgentAuthorizationRequest]) (*connect.Response[identitypb.GetAgentAuthorizationResponse], error) {
				gotSID := req.Header().Get(middleware.AuthenticatedSessionIDHeader)
				gotTime := req.Header().Get(middleware.AuthenticatedAuthTimeHeader)
				if (gotSID != "") != trustSession || (gotTime != "") != trustTime {
					t.Fatalf("session=%t authTime=%t forwarded SID=%q authTime=%q", trustSession, trustTime, gotSID, gotTime)
				}
				return connect.NewResponse(&identitypb.GetAgentAuthorizationResponse{}), nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
