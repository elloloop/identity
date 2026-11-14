package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// DirectoryKeyHeader carries a directory_reader project credential
// ("<public id>.<secret>") to the directory reads it authorizes, LookupUsers
// and MatchTenantMemberPhones. It is deliberately not the Authorization
// header: the JWT layer never sees it, so the credential cannot be confused
// with a session on any other RPC, and the handlers that verify it are the
// only code that reads it.
const DirectoryKeyHeader = "X-Directory-Key"

// LookupUsers resolves email addresses to active accounts for a service
// holding a directory_reader credential presented in DirectoryKeyHeader.
func (h *IdentityHandler) LookupUsers(
	ctx context.Context,
	req *connect.Request[identitypb.LookupUsersRequest],
) (*connect.Response[identitypb.LookupUsersResponse], error) {
	if h.directory == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	found, err := h.directory.LookupUsers(ctx, req.Header().Get(DirectoryKeyHeader), req.Msg.GetEmails())
	if err != nil {
		return nil, toConnectError(err)
	}
	users := make([]*identitypb.DirectoryUser, 0, len(found))
	for _, u := range found {
		users = append(users, &identitypb.DirectoryUser{
			Id:              u.ID,
			Email:           u.Email,
			Name:            u.Name,
			AvatarUrl:       u.AvatarURL,
			EmailVerified:   u.EmailVerified,
			RequestedEmails: u.RequestedEmails,
		})
	}
	return connect.NewResponse(&identitypb.LookupUsersResponse{Users: users}), nil
}

// MatchTenantMemberPhones matches phone-number hashes against a tenant's
// members for a service holding a directory_reader credential presented in
// DirectoryKeyHeader.
func (h *IdentityHandler) MatchTenantMemberPhones(
	ctx context.Context,
	req *connect.Request[identitypb.MatchTenantMemberPhonesRequest],
) (*connect.Response[identitypb.MatchTenantMemberPhonesResponse], error) {
	if h.directory == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userIDs, err := h.directory.MatchTenantMemberPhones(ctx, req.Header().Get(DirectoryKeyHeader), req.Msg.GetTenantId(), req.Msg.GetPhoneNumberHashes())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.MatchTenantMemberPhonesResponse{UserIds: userIDs}), nil
}
