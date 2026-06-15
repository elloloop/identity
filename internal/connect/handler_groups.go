package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// ─── Group RPCs ─────────────────────────────────────────────────────────────

// CreateGroup creates a new group.
func (h *IdentityHandler) CreateGroup(
	ctx context.Context,
	req *connect.Request[identitypb.CreateGroupRequest],
) (*connect.Response[identitypb.CreateGroupResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	group, err := h.groups.CreateGroup(
		ctx, callerID, req.Msg.Name, req.Msg.Description,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.CreateGroupResponse{
		Group: groupToProto(group),
	}
	return connect.NewResponse(resp), nil
}

// UpdateGroup updates a group's name and/or description.
func (h *IdentityHandler) UpdateGroup(
	ctx context.Context,
	req *connect.Request[identitypb.UpdateGroupRequest],
) (*connect.Response[identitypb.UpdateGroupResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	group, err := h.groups.UpdateGroup(
		ctx, callerID, req.Msg.GroupId, req.Msg.Name, req.Msg.Description,
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.UpdateGroupResponse{
		Group: groupToProto(group),
	}
	return connect.NewResponse(resp), nil
}

// DeleteGroup deletes a group.
func (h *IdentityHandler) DeleteGroup(
	ctx context.Context,
	req *connect.Request[identitypb.DeleteGroupRequest],
) (*connect.Response[identitypb.DeleteGroupResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.groups.DeleteGroup(ctx, callerID, req.Msg.GroupId)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.DeleteGroupResponse{}), nil
}

// ListGroups returns a paginated list of groups.
func (h *IdentityHandler) ListGroups(
	ctx context.Context,
	req *connect.Request[identitypb.ListGroupsRequest],
) (*connect.Response[identitypb.ListGroupsResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	groups, nextCursor, err := h.groups.ListGroups(
		ctx, callerID, req.Msg.Cursor, int(req.Msg.Limit),
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.ListGroupsResponse{
		Groups:     groupsToProto(groups),
		NextCursor: nextCursor,
	}
	return connect.NewResponse(resp), nil
}

// ─── Membership RPCs ────────────────────────────────────────────────────────

// AddGroupMember adds a user to a group.
func (h *IdentityHandler) AddGroupMember(
	ctx context.Context,
	req *connect.Request[identitypb.AddGroupMemberRequest],
) (*connect.Response[identitypb.AddGroupMemberResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.groups.AddGroupMember(ctx, callerID, req.Msg.GroupId, req.Msg.UserId)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.AddGroupMemberResponse{}), nil
}

// RemoveGroupMember removes a user from a group.
func (h *IdentityHandler) RemoveGroupMember(
	ctx context.Context,
	req *connect.Request[identitypb.RemoveGroupMemberRequest],
) (*connect.Response[identitypb.RemoveGroupMemberResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	err := h.groups.RemoveGroupMember(ctx, callerID, req.Msg.GroupId, req.Msg.UserId)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.RemoveGroupMemberResponse{}), nil
}

// ListGroupMembers lists all members of a group.
func (h *IdentityHandler) ListGroupMembers(
	ctx context.Context,
	req *connect.Request[identitypb.ListGroupMembersRequest],
) (*connect.Response[identitypb.ListGroupMembersResponse], error) {
	callerID := authenticatedUserID(req.Header())
	if callerID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	members, err := h.groups.ListGroupMembers(ctx, callerID, req.Msg.GroupId)
	if err != nil {
		return nil, toConnectError(err)
	}

	resp := &identitypb.ListGroupMembersResponse{
		Members: usersToProto(members),
	}
	return connect.NewResponse(resp), nil
}
