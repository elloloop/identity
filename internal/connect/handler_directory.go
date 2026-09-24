package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

// LookupUsers resolves email addresses to active accounts for a service
// holding a directory_reader credential. The credential arrives in the
// DirectoryKeyHeader, never the Authorization header, so no JWT-verifying layer
// ever mistakes it for a session — and no RPC but this one reads it.
func (h *IdentityHandler) LookupUsers(
	ctx context.Context,
	req *connect.Request[identitypb.LookupUsersRequest],
) (*connect.Response[identitypb.LookupUsersResponse], error) {
	if h.directory == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	found, err := h.directory.LookupUsers(ctx, req.Header().Get(middleware.DirectoryKeyHeader), req.Msg.GetEmails())
	if err != nil {
		return nil, toConnectError(err)
	}
	users := make([]*identitypb.DirectoryUser, 0, len(found))
	for _, u := range found {
		users = append(users, &identitypb.DirectoryUser{
			Id:            u.ID,
			Email:         u.Email,
			Name:          u.Name,
			AvatarUrl:     u.AvatarURL,
			EmailVerified: u.EmailVerified,
		})
	}
	return connect.NewResponse(&identitypb.LookupUsersResponse{Users: users}), nil
}
