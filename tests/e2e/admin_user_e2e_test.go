//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"
)

// TestE2E_Admin_InviteAcceptLogin drives user invitation, acceptance, and login.
func TestE2E_Admin_InviteAcceptLogin(t *testing.T) {
	requireGraphDB(t)
	t.Parallel()
	h := StartServer(t)

	// 1. Seed admin and login
	adminEmail := "admin-invite@example.com"
	h.SeedUser(t, adminEmail, "Admin User", "admin", "active", goodPassword)
	at, _ := h.Login(t, adminEmail, goodPassword)

	// 2. Admin invites a user
	inviteeEmail := "invitee-e2e@example.com"
	resp, status := h.rpcCall(t, "InviteUser", map[string]any{
		"email": inviteeEmail,
		"name":  "Invitee User",
		"role":  "member",
	}, at)
	if status != http.StatusOK {
		t.Fatalf("InviteUser status=%d, body=%v", status, resp)
	}
	invToken, _ := resp["invitationToken"].(string)
	if invToken == "" {
		t.Fatalf("invitationToken was empty")
	}
	userObj, _ := resp["user"].(map[string]any)
	inviteeID, _ := userObj["id"].(string)

	// 3. Trying to login before accepting invitation must fail
	_, status = h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    inviteeEmail,
		"password": "Invited!Pass9",
	}, "")
	if status == http.StatusOK {
		t.Fatalf("login should have failed for unaccepted invitation")
	}

	// 4. Accept Invitation (exempt from auth)
	resp, status = h.rpcCall(t, "AcceptInvitation", map[string]any{
		"invitationToken": invToken,
		"password":        "Invited!Pass9",
		"name":            "Invited and Active",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("AcceptInvitation status=%d, body=%v", status, resp)
	}
	acceptedUser, _ := resp["user"].(map[string]any)
	if acceptedUser["email"] != inviteeEmail {
		t.Errorf("accepted user email = %v, want %q", acceptedUser["email"], inviteeEmail)
	}
	acceptedAt, _ := resp["accessToken"].(string)
	if acceptedAt == "" {
		t.Fatalf("expected accessToken in AcceptInvitation response")
	}

	// 5. Verify user can now login
	newAt, _ := h.Login(t, inviteeEmail, "Invited!Pass9")
	if newAt == "" {
		t.Fatalf("login with invited user failed")
	}

	// 6. Admin deactivates the user
	resp, status = h.rpcCall(t, "DeactivateUser", map[string]any{
		"userId": inviteeID,
		"reason": "deactivation test",
	}, at)
	if status != http.StatusOK {
		t.Fatalf("DeactivateUser status=%d, body=%v", status, resp)
	}

	// 7. Login should now fail because user is deactivated
	_, status = h.rpcCall(t, "PasswordLogin", map[string]any{
		"email":    inviteeEmail,
		"password": "Invited!Pass9",
	}, "")
	if status == http.StatusOK {
		t.Fatalf("deactivated user login unexpectedly succeeded")
	}

	// 8. Admin reactivates the user
	resp, status = h.rpcCall(t, "ReactivateUser", map[string]any{
		"userId": inviteeID,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("ReactivateUser status=%d, body=%v", status, resp)
	}

	// 9. Login works again
	newAt2, _ := h.Login(t, inviteeEmail, "Invited!Pass9")
	if newAt2 == "" {
		t.Fatalf("login after reactivation failed")
	}
}

// TestE2E_Admin_UserCRUD drives standard admin User CRUD flows.
func TestE2E_Admin_UserCRUD(t *testing.T) {
	requireGraphDB(t)
	t.Parallel()
	h := StartServer(t)

	// 1. Seed admin and login
	adminEmail := "admin-crud@example.com"
	h.SeedUser(t, adminEmail, "Admin User", "admin", "active", goodPassword)
	at, _ := h.Login(t, adminEmail, goodPassword)

	// 2. Admin creates a user directly
	targetEmail := "target-crud-e2e@example.com"
	resp, status := h.rpcCall(t, "CreateUser", map[string]any{
		"email":     targetEmail,
		"name":      "Target User",
		"avatarUrl": "https://example.com/avatar.png",
		"role":      "member",
	}, at)
	if status != http.StatusOK {
		t.Fatalf("CreateUser status=%d, body=%v", status, resp)
	}
	userObj, _ := resp["user"].(map[string]any)
	userID, _ := userObj["id"].(string)
	if userID == "" {
		t.Fatalf("expected non-empty created user ID")
	}

	// 3. Get User
	resp, status = h.rpcCall(t, "GetUser", map[string]any{
		"userId": userID,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("GetUser status=%d, body=%v", status, resp)
	}
	fetchedUser, _ := resp["user"].(map[string]any)
	if fetchedUser["email"] != targetEmail {
		t.Errorf("fetched user email = %v, want %q", fetchedUser["email"], targetEmail)
	}

	// 4. List Users
	resp, status = h.rpcCall(t, "ListUsers", map[string]any{
		"limit": 10,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("ListUsers status=%d, body=%v", status, resp)
	}
	users, _ := resp["users"].([]any)
	if len(users) < 2 { // Admin + Target User
		t.Errorf("expected at least 2 users in list, got %d", len(users))
	}

	// 5. Update User
	resp, status = h.rpcCall(t, "UpdateUser", map[string]any{
		"userId":    userID,
		"name":      "Updated Target Name",
		"avatarUrl": "https://example.com/avatar2.png",
		"role":      "guest",
	}, at)
	if status != http.StatusOK {
		t.Fatalf("UpdateUser status=%d, body=%v", status, resp)
	}
	updatedUser, _ := resp["user"].(map[string]any)
	if updatedUser["name"] != "Updated Target Name" {
		t.Errorf("updated name = %v, want 'Updated Target Name'", updatedUser["name"])
	}
	if updatedUser["role"] != "guest" {
		t.Errorf("updated role = %v, want 'guest'", updatedUser["role"])
	}

	// 6. Set User Quota
	resp, status = h.rpcCall(t, "SetUserQuota", map[string]any{
		"userId":     userID,
		"quotaBytes": 50000,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("SetUserQuota status=%d, body=%v", status, resp)
	}

	// Get User to check quota (with retry for eventual consistency)
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, _ = h.rpcCall(t, "GetUser", map[string]any{"userId": userID}, at)
		fetchedUser, _ = resp["user"].(map[string]any)
		quotaStr, _ := fetchedUser["quotaBytes"].(string)
		if quotaStr == "50000" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("quotaBytes = %q, want \"50000\"", quotaStr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 7. Reset User Password
	resp, status = h.rpcCall(t, "ResetUserPassword", map[string]any{
		"userId":               userID,
		"generateTempPassword": true,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("ResetUserPassword status=%d, body=%v", status, resp)
	}
	tempPW, _ := resp["temporaryPassword"].(string)
	if tempPW == "" {
		t.Fatalf("temporaryPassword was empty")
	}

	// Verify temporary password works for login
	targetAt, _ := h.Login(t, targetEmail, tempPW)
	if targetAt == "" {
		t.Fatalf("login with temporary password failed")
	}

	// 8. Delete User
	resp, status = h.rpcCall(t, "DeleteUser", map[string]any{
		"userId": userID,
	}, at)
	if status != http.StatusOK {
		t.Fatalf("DeleteUser status=%d, body=%v", status, resp)
	}

	// Verify GetUser returns non-200 (with retry for eventual consistency)
	deadline = time.Now().Add(3 * time.Second)
	for {
		_, status = h.rpcCall(t, "GetUser", map[string]any{"userId": userID}, at)
		if status != http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("GetUser unexpectedly succeeded after deletion")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
