//go:build integration

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
)

func TestAdmin_InviteAcceptLogin_E2E(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()

	seedIssue3User(t, h, "admin-1", "admin@example.com", "Admin", "admin", "active", goodPassword)
	admin := h.AuthedClient(loginViaPassword(t, h, "admin@example.com", goodPassword).AccessToken)

	invite, err := admin.InviteUser(ctx, connect.NewRequest(&identitypb.InviteUserRequest{
		Email: "invitee@example.com",
		Name:  "Invitee",
		Role:  "member",
	}))
	if err != nil {
		t.Fatalf("InviteUser: %v", err)
	}
	if invite.Msg.GetInvitationToken() == "" {
		t.Fatalf("InviteUser returned empty invitation token")
	}

	_, err = h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "invitee@example.com",
		Password: "Invited!Pass9",
	}))
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("login before AcceptInvitation code = %v, want FailedPrecondition (err=%v)", got, err)
	}

	accepted, err := h.Client.AcceptInvitation(ctx, connect.NewRequest(&identitypb.AcceptInvitationRequest{
		InvitationToken: invite.Msg.InvitationToken,
		Password:        "Invited!Pass9",
		Name:            "Invited User",
	}))
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if accepted.Msg.GetUser().GetEmail() != "invitee@example.com" {
		t.Fatalf("accepted user email = %q, want invitee@example.com", accepted.Msg.GetUser().GetEmail())
	}
	if accepted.Msg.AccessToken == "" {
		t.Fatalf("AcceptInvitation returned empty access token")
	}

	login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "invitee@example.com",
		Password: "Invited!Pass9",
	}))
	if err != nil {
		t.Fatalf("PasswordLogin after AcceptInvitation: %v", err)
	}
	if login.Msg.GetUser().GetId() != invite.Msg.GetUser().GetId() {
		t.Fatalf("login user id = %q, want %q", login.Msg.GetUser().GetId(), invite.Msg.GetUser().GetId())
	}
}

func TestAdmin_DeactivateBlocksLogin(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()

	seedIssue3User(t, h, "admin-1", "admin@example.com", "Admin", "admin", "active", goodPassword)
	seedIssue3User(t, h, "member-1", "member@example.com", "Member", "member", "active", goodPassword)

	admin := h.AuthedClient(loginViaPassword(t, h, "admin@example.com", goodPassword).AccessToken)
	if _, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "member@example.com",
		Password: goodPassword,
	})); err != nil {
		t.Fatalf("member login before deactivation: %v", err)
	}

	if _, err := admin.DeactivateUser(ctx, connect.NewRequest(&identitypb.DeactivateUserRequest{
		UserId: "member-1",
		Reason: "end-to-end test",
	})); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}

	_, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "member@example.com",
		Password: goodPassword,
	}))
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("login after deactivation code = %v, want FailedPrecondition (err=%v)", got, err)
	}
}

func TestAdmin_ResetUserPassword_TempPassword(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()

	seedIssue3User(t, h, "admin-1", "admin@example.com", "Admin", "admin", "active", goodPassword)
	seedIssue3User(t, h, "member-1", "member@example.com", "Member", "member", "active", goodPassword)

	admin := h.AuthedClient(loginViaPassword(t, h, "admin@example.com", goodPassword).AccessToken)
	reset, err := admin.ResetUserPassword(ctx, connect.NewRequest(&identitypb.ResetUserPasswordRequest{
		UserId:               "member-1",
		GenerateTempPassword: true,
	}))
	if err != nil {
		t.Fatalf("ResetUserPassword temp: %v", err)
	}
	if reset.Msg.GetTemporaryPassword() == "" {
		t.Fatalf("expected temporary password from ResetUserPassword")
	}
	if reset.Msg.GetResetToken() != "" {
		t.Fatalf("expected empty reset token when temp password is requested")
	}

	login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "member@example.com",
		Password: reset.Msg.TemporaryPassword,
	}))
	if err != nil {
		t.Fatalf("login with temporary password: %v", err)
	}
	if login.Msg.GetUser().GetId() != "member-1" {
		t.Fatalf("temp-password login user id = %q, want member-1", login.Msg.GetUser().GetId())
	}

	_, err = h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "member@example.com",
		Password: goodPassword,
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("old password after temp reset code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

func TestAdmin_ResetUserPassword_ResetToken(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()

	seedIssue3User(t, h, "admin-1", "admin@example.com", "Admin", "admin", "active", goodPassword)
	seedIssue3User(t, h, "member-1", "member@example.com", "Member", "member", "active", goodPassword)

	admin := h.AuthedClient(loginViaPassword(t, h, "admin@example.com", goodPassword).AccessToken)
	reset, err := admin.ResetUserPassword(ctx, connect.NewRequest(&identitypb.ResetUserPasswordRequest{
		UserId:               "member-1",
		GenerateTempPassword: false,
	}))
	if err != nil {
		t.Fatalf("ResetUserPassword token: %v", err)
	}
	if reset.Msg.GetResetToken() == "" {
		t.Fatalf("expected reset token from ResetUserPassword")
	}
	if reset.Msg.GetTemporaryPassword() != "" {
		t.Fatalf("expected empty temporary password when reset token is requested")
	}

	if _, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "member@example.com",
		Password: goodPassword,
	})); err != nil {
		t.Fatalf("old password should still work before ConfirmPasswordReset: %v", err)
	}

	if _, err := h.Client.ConfirmPasswordReset(ctx, connect.NewRequest(&identitypb.ConfirmPasswordResetRequest{
		Token:       reset.Msg.ResetToken,
		NewPassword: "Reset!Pass42",
	})); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}

	if _, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "member@example.com",
		Password: "Reset!Pass42",
	})); err != nil {
		t.Fatalf("login with reset password: %v", err)
	}

	_, err = h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    "member@example.com",
		Password: goodPassword,
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("old password after ConfirmPasswordReset code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

func TestAdmin_NonAdminDenied(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()

	seedIssue3User(t, h, "admin-1", "admin@example.com", "Admin", "admin", "active", goodPassword)
	seedIssue3User(t, h, "member-1", "member@example.com", "Member", "member", "active", goodPassword)
	seedIssue3User(t, h, "target-1", "target@example.com", "Target", "member", "active", goodPassword)

	member := h.AuthedClient(loginViaPassword(t, h, "member@example.com", goodPassword).AccessToken)

	cases := []struct {
		name string
		call func() error
	}{
		{
			name: "InviteUser",
			call: func() error {
				_, err := member.InviteUser(ctx, connect.NewRequest(&identitypb.InviteUserRequest{
					Email: "new@example.com",
					Role:  "member",
				}))
				return err
			},
		},
		{
			name: "ListUsers",
			call: func() error {
				_, err := member.ListUsers(ctx, connect.NewRequest(&identitypb.ListUsersRequest{Limit: 10}))
				return err
			},
		},
		{
			name: "GetUser",
			call: func() error {
				_, err := member.GetUser(ctx, connect.NewRequest(&identitypb.GetUserRequest{UserId: "target-1"}))
				return err
			},
		},
		{
			name: "UpdateUser",
			call: func() error {
				_, err := member.UpdateUser(ctx, connect.NewRequest(&identitypb.UpdateUserRequest{
					UserId: "target-1",
					Name:   "Updated",
				}))
				return err
			},
		},
		{
			name: "DeactivateUser",
			call: func() error {
				_, err := member.DeactivateUser(ctx, connect.NewRequest(&identitypb.DeactivateUserRequest{
					UserId: "target-1",
					Reason: "test",
				}))
				return err
			},
		},
		{
			name: "ReactivateUser",
			call: func() error {
				_, err := member.ReactivateUser(ctx, connect.NewRequest(&identitypb.ReactivateUserRequest{
					UserId: "target-1",
				}))
				return err
			},
		},
		{
			name: "ResetUserPassword",
			call: func() error {
				_, err := member.ResetUserPassword(ctx, connect.NewRequest(&identitypb.ResetUserPasswordRequest{
					UserId:               "target-1",
					GenerateTempPassword: true,
				}))
				return err
			},
		},
		{
			name: "SetUserQuota",
			call: func() error {
				_, err := member.SetUserQuota(ctx, connect.NewRequest(&identitypb.SetUserQuotaRequest{
					UserId:     "target-1",
					QuotaBytes: 1024,
				}))
				return err
			},
		},
		{
			name: "CreateUser",
			call: func() error {
				_, err := member.CreateUser(ctx, connect.NewRequest(&identitypb.CreateUserRequest{
					Email: "create@example.com",
					Role:  "member",
				}))
				return err
			},
		},
		{
			name: "DeleteUser",
			call: func() error {
				_, err := member.DeleteUser(ctx, connect.NewRequest(&identitypb.DeleteUserRequest{
					UserId: "target-1",
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
