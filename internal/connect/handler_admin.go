package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// ─── Admin User Management RPCs ─────────────────────────────────────────────
// All RPCs in this section require the caller's JWT to carry role=admin.
// Authorization is enforced in the service layer.

// InviteUser creates a new user invitation or immediately creates an active user.
func (h *IdentityHandler) InviteUser(
	ctx context.Context,
	req *connect.Request[identitypb.InviteUserRequest],
) (*connect.Response[identitypb.InviteUserResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	result, err := h.admin.InviteUser(
		ctx,
		callerID,
		req.Msg.Email,
		req.Msg.Name,
		req.Msg.Role,
		req.Msg.RecoveryEmail,
		req.Msg.QuotaBytes,
		req.Msg.CreateImmediately,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.InviteUserResponse{
		User:              userToProto(result.User),
		InvitationToken:   result.InvitationToken,
		SetupUrl:          result.SetupURL,
		TemporaryPassword: result.TemporaryPassword,
	}
	return connect.NewResponse(resp), nil
}

// ListUsers returns a paginated list of users. Admin only.
func (h *IdentityHandler) ListUsers(
	ctx context.Context,
	req *connect.Request[identitypb.ListUsersRequest],
) (*connect.Response[identitypb.ListUsersResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	statusFilter := protoToUserStatusString(req.Msg.StatusFilter)

	users, nextCursor, totalCount, err := h.admin.ListUsers(
		ctx,
		callerID,
		statusFilter,
		req.Msg.Search,
		req.Msg.Cursor,
		int(req.Msg.Limit),
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.ListUsersResponse{
		Users:      usersToProto(users),
		NextCursor: nextCursor,
		TotalCount: intToProtoInt32(totalCount),
	}
	return connect.NewResponse(resp), nil
}

// GetUser returns a single user by ID. Admin only.
func (h *IdentityHandler) GetUser(
	ctx context.Context,
	req *connect.Request[identitypb.GetUserRequest],
) (*connect.Response[identitypb.GetUserResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	user, err := h.admin.GetUser(ctx, callerID, req.Msg.UserId)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.GetUserResponse{
		User: userToProto(user),
	}
	return connect.NewResponse(resp), nil
}

// UpdateUser updates a user's profile fields. Admin only.
func (h *IdentityHandler) UpdateUser(
	ctx context.Context,
	req *connect.Request[identitypb.UpdateUserRequest],
) (*connect.Response[identitypb.UpdateUserResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	user, err := h.admin.UpdateUser(
		ctx,
		callerID,
		req.Msg.UserId,
		req.Msg.Name,
		req.Msg.Role,
		req.Msg.AvatarUrl,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.UpdateUserResponse{
		User: userToProto(user),
	}
	return connect.NewResponse(resp), nil
}

// DeactivateUser deactivates a user account. Admin only.
func (h *IdentityHandler) DeactivateUser(
	ctx context.Context,
	req *connect.Request[identitypb.DeactivateUserRequest],
) (*connect.Response[identitypb.DeactivateUserResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.admin.DeactivateUser(ctx, callerID, req.Msg.UserId, req.Msg.Reason)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.DeactivateUserResponse{}), nil
}

// ReactivateUser reactivates a previously deactivated user. Admin only.
func (h *IdentityHandler) ReactivateUser(
	ctx context.Context,
	req *connect.Request[identitypb.ReactivateUserRequest],
) (*connect.Response[identitypb.ReactivateUserResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.admin.ReactivateUser(ctx, callerID, req.Msg.UserId)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.ReactivateUserResponse{}), nil
}

// ResetUserPassword resets a user's password. Admin only.
func (h *IdentityHandler) ResetUserPassword(
	ctx context.Context,
	req *connect.Request[identitypb.ResetUserPasswordRequest],
) (*connect.Response[identitypb.ResetUserPasswordResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	result, err := h.admin.ResetUserPassword(
		ctx, callerID, req.Msg.UserId, req.Msg.GenerateTempPassword,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.ResetUserPasswordResponse{
		TemporaryPassword: result.TemporaryPassword,
		ResetToken:        result.ResetToken,
	}
	return connect.NewResponse(resp), nil
}

// SetUserQuota sets a user's storage quota. Admin only.
func (h *IdentityHandler) SetUserQuota(
	ctx context.Context,
	req *connect.Request[identitypb.SetUserQuotaRequest],
) (*connect.Response[identitypb.SetUserQuotaResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.admin.SetUserQuota(ctx, callerID, req.Msg.UserId, req.Msg.QuotaBytes)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.SetUserQuotaResponse{}), nil
}

// ─── CRUD User RPCs ─────────────────────────────────────────────────────────
// Lower-level CRUD operations from the proto service definition.

// CreateUser creates a new user. Admin only.
// Delegates to InviteUser with createImmediately=true.
func (h *IdentityHandler) CreateUser(
	ctx context.Context,
	req *connect.Request[identitypb.CreateUserRequest],
) (*connect.Response[identitypb.CreateUserResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	result, err := h.admin.InviteUser(
		ctx, callerID, req.Msg.Email, req.Msg.Name, req.Msg.Role,
		"",   // recoveryEmail
		0,    // quotaBytes
		true, // createImmediately
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.CreateUserResponse{
		User: userToProto(result.User),
	}
	return connect.NewResponse(resp), nil
}

// DeleteUser physically removes a user and cascades all user-owned
// records (sessions, tokens, passkeys, etc.). Audit events are
// retained. Admin only.
func (h *IdentityHandler) DeleteUser(
	ctx context.Context,
	req *connect.Request[identitypb.DeleteUserRequest],
) (*connect.Response[identitypb.DeleteUserResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	if err := h.admin.DeleteUser(ctx, callerID, req.Msg.UserId); err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.DeleteUserResponse{}), nil
}
