//go:build integration || realpostgres

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
)

func TestGroup_CRUDRoundTrip_E2E(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()
	adminEmail := issue3Email(t, "admin@example.com")

	seedIssue3User(t, h, adminEmail, "Admin", "admin", "active", issue3Password)
	admin := h.AuthedClient(loginViaPassword(t, h, adminEmail, issue3Password).AccessToken)

	created, err := admin.CreateGroup(ctx, connect.NewRequest(&identitypb.CreateGroupRequest{
		Name:        "Engineering",
		Description: "Original description",
	}))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	groupID := created.Msg.GetGroup().GetId()
	if groupID == "" {
		t.Fatalf("CreateGroup returned empty group id")
	}

	listed, err := admin.ListGroups(ctx, connect.NewRequest(&identitypb.ListGroupsRequest{Limit: 10}))
	if err != nil {
		t.Fatalf("ListGroups after create: %v", err)
	}
	if len(listed.Msg.Groups) != 1 || listed.Msg.Groups[0].GetId() != groupID {
		t.Fatalf("ListGroups after create = %+v, want one group %q", listed.Msg.Groups, groupID)
	}

	updated, err := admin.UpdateGroup(ctx, connect.NewRequest(&identitypb.UpdateGroupRequest{
		GroupId:     groupID,
		Name:        "Platform",
		Description: "Updated description",
	}))
	if err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	if updated.Msg.GetGroup().GetName() != "Platform" {
		t.Fatalf("updated name = %q, want Platform", updated.Msg.GetGroup().GetName())
	}

	_, err = admin.CreateGroup(ctx, connect.NewRequest(&identitypb.CreateGroupRequest{}))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("CreateGroup missing name code = %v, want InvalidArgument (err=%v)", got, err)
	}

	if _, err := admin.DeleteGroup(ctx, connect.NewRequest(&identitypb.DeleteGroupRequest{GroupId: groupID})); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}

	afterDelete, err := admin.ListGroups(ctx, connect.NewRequest(&identitypb.ListGroupsRequest{Limit: 10}))
	if err != nil {
		t.Fatalf("ListGroups after delete: %v", err)
	}
	if len(afterDelete.Msg.Groups) != 0 {
		t.Fatalf("expected zero groups after delete, got %d", len(afterDelete.Msg.Groups))
	}
}

func TestGroup_MemberRoundTrip_E2E(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()
	adminEmail := issue3Email(t, "admin@example.com")
	memberEmail := issue3Email(t, "member@example.com")

	seedIssue3User(t, h, adminEmail, "Admin", "admin", "active", issue3Password)
	memberID := seedIssue3User(t, h, memberEmail, "Member", "member", "active", issue3Password)
	admin := h.AuthedClient(loginViaPassword(t, h, adminEmail, issue3Password).AccessToken)

	created, err := admin.CreateGroup(ctx, connect.NewRequest(&identitypb.CreateGroupRequest{
		Name:        "Operations",
		Description: "Team",
	}))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	groupID := created.Msg.GetGroup().GetId()

	if _, err := admin.AddGroupMember(ctx, connect.NewRequest(&identitypb.AddGroupMemberRequest{
		GroupId: groupID,
		UserId:  memberID,
	})); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}

	members, err := admin.ListGroupMembers(ctx, connect.NewRequest(&identitypb.ListGroupMembersRequest{
		GroupId: groupID,
	}))
	if err != nil {
		t.Fatalf("ListGroupMembers after add: %v", err)
	}
	if len(members.Msg.Members) != 1 || members.Msg.Members[0].GetId() != memberID {
		t.Fatalf("members after add = %+v, want %q present", members.Msg.Members, memberID)
	}

	if _, err := admin.RemoveGroupMember(ctx, connect.NewRequest(&identitypb.RemoveGroupMemberRequest{
		GroupId: groupID,
		UserId:  memberID,
	})); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}

	members, err = admin.ListGroupMembers(ctx, connect.NewRequest(&identitypb.ListGroupMembersRequest{
		GroupId: groupID,
	}))
	if err != nil {
		t.Fatalf("ListGroupMembers after remove: %v", err)
	}
	if len(members.Msg.Members) != 0 {
		t.Fatalf("expected zero members after remove, got %d", len(members.Msg.Members))
	}

	_, err = admin.ListGroupMembers(ctx, connect.NewRequest(&identitypb.ListGroupMembersRequest{}))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("ListGroupMembers missing group id code = %v, want InvalidArgument (err=%v)", got, err)
	}
}

// TestGroup_DeleteDrainsMemberEdges_E2E proves DeleteGroup removes the
// inbound MEMBER_OF edges along with the group node. Before the fix the
// edges dangled on the graph backend, so ListGroupMembers on the deleted
// group still resolved the orphaned member.
func TestGroup_DeleteDrainsMemberEdges_E2E(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()
	adminEmail := issue3Email(t, "admin@example.com")
	memberEmail := issue3Email(t, "member@example.com")

	seedIssue3User(t, h, adminEmail, "Admin", "admin", "active", issue3Password)
	memberID := seedIssue3User(t, h, memberEmail, "Member", "member", "active", issue3Password)
	admin := h.AuthedClient(loginViaPassword(t, h, adminEmail, issue3Password).AccessToken)

	created, err := admin.CreateGroup(ctx, connect.NewRequest(&identitypb.CreateGroupRequest{
		Name:        "Doomed",
		Description: "deleted while it still has a member",
	}))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	groupID := created.Msg.GetGroup().GetId()

	if _, err := admin.AddGroupMember(ctx, connect.NewRequest(&identitypb.AddGroupMemberRequest{
		GroupId: groupID,
		UserId:  memberID,
	})); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}

	if _, err := admin.DeleteGroup(ctx, connect.NewRequest(&identitypb.DeleteGroupRequest{GroupId: groupID})); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}

	// The MEMBER_OF edge must be gone with the node; a dangling edge would
	// still resolve the member here.
	members, err := admin.ListGroupMembers(ctx, connect.NewRequest(&identitypb.ListGroupMembersRequest{
		GroupId: groupID,
	}))
	if err != nil {
		t.Fatalf("ListGroupMembers after delete: %v", err)
	}
	if len(members.Msg.Members) != 0 {
		t.Fatalf("DeleteGroup left %d dangling MEMBER_OF edge(s), want 0", len(members.Msg.Members))
	}
}

func TestGroup_NonAdminDenied(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()
	targetEmail := issue3Email(t, "target@example.com")
	adminEmail := issue3Email(t, "admin@example.com")
	memberEmail := issue3Email(t, "member@example.com")

	targetID := seedIssue3User(t, h, targetEmail, "Target", "member", "active", issue3Password)
	seedIssue3User(t, h, adminEmail, "Admin", "admin", "active", issue3Password)
	seedIssue3User(t, h, memberEmail, "Member", "member", "active", issue3Password)

	admin := h.AuthedClient(loginViaPassword(t, h, adminEmail, issue3Password).AccessToken)
	member := h.AuthedClient(loginViaPassword(t, h, memberEmail, issue3Password).AccessToken)

	created, err := admin.CreateGroup(ctx, connect.NewRequest(&identitypb.CreateGroupRequest{
		Name:        "SecOps",
		Description: "Existing group",
	}))
	if err != nil {
		t.Fatalf("admin CreateGroup: %v", err)
	}
	groupID := created.Msg.GetGroup().GetId()

	cases := []struct {
		name string
		call func() error
	}{
		{
			name: "CreateGroup",
			call: func() error {
				_, err := member.CreateGroup(ctx, connect.NewRequest(&identitypb.CreateGroupRequest{
					Name:        "Unauthorized",
					Description: "member should not create this",
				}))
				return err
			},
		},
		{
			name: "UpdateGroup",
			call: func() error {
				_, err := member.UpdateGroup(ctx, connect.NewRequest(&identitypb.UpdateGroupRequest{
					GroupId:     groupID,
					Name:        "Changed",
					Description: "Changed",
				}))
				return err
			},
		},
		{
			name: "AddGroupMember",
			call: func() error {
				_, err := member.AddGroupMember(ctx, connect.NewRequest(&identitypb.AddGroupMemberRequest{
					GroupId: groupID,
					UserId:  targetID,
				}))
				return err
			},
		},
		{
			name: "RemoveGroupMember",
			call: func() error {
				_, err := member.RemoveGroupMember(ctx, connect.NewRequest(&identitypb.RemoveGroupMemberRequest{
					GroupId: groupID,
					UserId:  targetID,
				}))
				return err
			},
		},
		{
			name: "DeleteGroup",
			call: func() error {
				_, err := member.DeleteGroup(ctx, connect.NewRequest(&identitypb.DeleteGroupRequest{
					GroupId: groupID,
				}))
				return err
			},
		},
	}

	for _, tc := range cases {
		if got := connect.CodeOf(tc.call()); got != connect.CodePermissionDenied {
			t.Fatalf("%s code = %v, want PermissionDenied", tc.name, got)
		}
	}
}
