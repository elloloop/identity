//go:build e2e

package e2e

import (
	"net/http"
	"testing"
)

func TestE2E_Group_CRUDRoundTrip(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	// 1. Seed an admin user and login
	adminEmail := "admin-crud@example.com"
	h.SeedUser(t, adminEmail, "Admin User", "admin", "active", goodPassword)
	at, _ := h.Login(t, adminEmail, goodPassword)

	// 2. Create Group
	resp, status := h.rpcCall(t, "CreateGroup", map[string]any{
		"name":        "Engineering",
		"description": "Original description",
	}, at)
	if status != http.StatusOK {
		t.Fatalf("CreateGroup status=%d, body=%v", status, resp)
	}
	group, _ := resp["group"].(map[string]any)
	if group == nil {
		t.Fatalf("expected created group, got nil")
	}
	groupID, _ := group["id"].(string)
	if groupID == "" {
		t.Fatalf("created group had empty ID")
	}
	if group["name"] != "Engineering" {
		t.Errorf("group name = %v, want Engineering", group["name"])
	}

	// 3. List Groups
	resp, status = h.rpcCall(t, "ListGroups", map[string]any{
		"limit": 10,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("ListGroups status=%d, body=%v", status, resp)
	}
	groups, _ := resp["groups"].([]any)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	firstGroup, _ := groups[0].(map[string]any)
	if firstGroup["id"] != groupID {
		t.Errorf("listed group ID = %v, want %q", firstGroup["id"], groupID)
	}

	// 4. Update Group
	resp, status = h.rpcCall(t, "UpdateGroup", map[string]any{
		"groupId":     groupID,
		"name":        "Platform",
		"description": "Updated description",
	}, at)
	if status != http.StatusOK {
		t.Fatalf("UpdateGroup status=%d, body=%v", status, resp)
	}
	updatedGroup, _ := resp["group"].(map[string]any)
	if updatedGroup["name"] != "Platform" {
		t.Errorf("updated name = %v, want Platform", updatedGroup["name"])
	}
	if updatedGroup["description"] != "Updated description" {
		t.Errorf("updated desc = %v, want Updated description", updatedGroup["description"])
	}

	// 5. Create Group validation error
	resp, status = h.rpcCall(t, "CreateGroup", map[string]any{}, at)
	if status == http.StatusOK {
		t.Fatalf("expected CreateGroup with missing name to be rejected, got 200")
	}

	// 6. Delete Group
	resp, status = h.rpcCall(t, "DeleteGroup", map[string]any{
		"groupId": groupID,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("DeleteGroup status=%d, body=%v", status, resp)
	}

	// 7. Verify deletion
	resp, status = h.rpcCall(t, "ListGroups", map[string]any{
		"limit": 10,
	}, at)
	groups, _ = resp["groups"].([]any)
	if len(groups) != 0 {
		t.Fatalf("expected 0 groups after delete, got %d", len(groups))
	}
}

func TestE2E_Group_MemberRoundTrip(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	// 1. Seed admin and a member user
	adminEmail := "admin-member@example.com"
	h.SeedUser(t, adminEmail, "Admin User", "admin", "active", goodPassword)
	at, _ := h.Login(t, adminEmail, goodPassword)

	memberEmail := "member-flow@example.com"
	_, _, memberID := h.Signup(t, memberEmail, goodPassword)

	// 2. Create a group
	resp, _ := h.rpcCall(t, "CreateGroup", map[string]any{
		"name":        "Operations",
		"description": "Team",
	}, at)
	group, _ := resp["group"].(map[string]any)
	groupID, _ := group["id"].(string)

	// 3. Add Group Member
	resp, status := h.rpcCall(t, "AddGroupMember", map[string]any{
		"groupId": groupID,
		"userId":  memberID,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("AddGroupMember status=%d, body=%v", status, resp)
	}

	// 4. List Group Members
	resp, status = h.rpcCall(t, "ListGroupMembers", map[string]any{
		"groupId": groupID,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("ListGroupMembers status=%d, body=%v", status, resp)
	}
	members, _ := resp["members"].([]any)
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}
	firstMember, _ := members[0].(map[string]any)
	if firstMember["id"] != memberID {
		t.Errorf("member ID = %v, want %q", firstMember["id"], memberID)
	}

	// 5. Remove Group Member
	resp, status = h.rpcCall(t, "RemoveGroupMember", map[string]any{
		"groupId": groupID,
		"userId":  memberID,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("RemoveGroupMember status=%d, body=%v", status, resp)
	}

	// 6. Verify removal
	resp, status = h.rpcCall(t, "ListGroupMembers", map[string]any{
		"groupId": groupID,
	}, at)
	members, _ = resp["members"].([]any)
	if len(members) != 0 {
		t.Fatalf("expected 0 members, got %d", len(members))
	}

	// 7. List members missing group id validation error
	resp, status = h.rpcCall(t, "ListGroupMembers", map[string]any{}, at)
	if status == http.StatusOK {
		t.Fatalf("expected ListGroupMembers with missing group id to fail, got 200")
	}
}

func TestE2E_Group_NonAdminDenied(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	// 1. Seed admin and create group
	adminEmail := "admin-deny@example.com"
	h.SeedUser(t, adminEmail, "Admin User", "admin", "active", goodPassword)
	adminAt, _ := h.Login(t, adminEmail, goodPassword)

	resp, _ := h.rpcCall(t, "CreateGroup", map[string]any{
		"name":        "SecOps",
		"description": "Existing group",
	}, adminAt)
	group, _ := resp["group"].(map[string]any)
	groupID, _ := group["id"].(string)

	// 2. Signup a non-admin member
	memberEmail := "member-deny@example.com"
	memberAt, _, memberID := h.Signup(t, memberEmail, goodPassword)

	// 3. Verify non-admin is denied for all writing endpoints
	cases := []struct {
		name   string
		method string
		body   map[string]any
	}{
		{
			name:   "CreateGroup",
			method: "CreateGroup",
			body: map[string]any{
				"name":        "Unauthorized",
				"description": "unauthorized create",
			},
		},
		{
			name:   "UpdateGroup",
			method: "UpdateGroup",
			body: map[string]any{
				"groupId":     groupID,
				"name":        "Changed",
				"description": "changed",
			},
		},
		{
			name:   "AddGroupMember",
			method: "AddGroupMember",
			body: map[string]any{
				"groupId": groupID,
				"userId":  memberID,
			},
		},
		{
			name:   "RemoveGroupMember",
			method: "RemoveGroupMember",
			body: map[string]any{
				"groupId": groupID,
				"userId":  memberID,
			},
		},
		{
			name:   "DeleteGroup",
			method: "DeleteGroup",
			body: map[string]any{
				"groupId": groupID,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp, status := h.rpcCall(t, tc.method, tc.body, memberAt)
			if status == http.StatusOK {
				t.Fatalf("%s unexpectedly succeeded (status=200) for non-admin user", tc.name)
			}
			// In Connect-RPC, unauthorized usually maps to 403 (PermissionDenied).
			if status != http.StatusForbidden && status != http.StatusUnauthorized {
				t.Logf("%s returned status %d, body %v", tc.name, status, resp)
			}
		})
	}
}
