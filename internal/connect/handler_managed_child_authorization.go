package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

const ManagedChildKeyHeader = "X-Managed-Child-Key"

func (h *IdentityHandler) WithManagedChildAuthorization(s *service.ManagedChildAuthorizationService) *IdentityHandler {
	h.managedChildAuthorization = s
	return h
}

func (h *IdentityHandler) GetManagedChildAuthorization(ctx context.Context, req *connect.Request[identitypb.GetManagedChildAuthorizationRequest]) (*connect.Response[identitypb.GetManagedChildAuthorizationResponse], error) {
	if h.managedChildAuthorization == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	authorized, err := h.managedChildAuthorization.GetManagedChildAuthorization(ctx, req.Header().Get(ManagedChildKeyHeader), req.Msg.GetChildUserId(), req.Msg.GetGuardianUserId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.GetManagedChildAuthorizationResponse{Authorized: authorized}), nil
}
