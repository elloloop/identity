//go:build integration || realentdb || realpostgres

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
	adminEmail := issue3Email(t, "admin@example.com")
	inviteeEmail := issue3Email(t, "invitee@example.com")

	seedIssue3User(t, h, adminEmail, "Admin", "admin", "active", issue3Password)
	admin := h.AuthedClient(loginViaPassword(t, h, adminEmail, issue3Password).AccessToken)

	invite, err := admin.InviteUser(ctx, connect.NewRequest(&identitypb.InviteUserRequest{
		Email: inviteeEmail,
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
		Email:    inviteeEmail,
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
	if accepted.Msg.GetUser().GetEmail() != inviteeEmail {
		t.Fatalf("accepted user email = %q, want %q", accepted.Msg.GetUser().GetEmail(), inviteeEmail)
	}
	if accepted.Msg.AccessToken == "" {
		t.Fatalf("AcceptInvitation returned empty access token")
	}

	login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    inviteeEmail,
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
	adminEmail := issue3Email(t, "admin@example.com")
	memberEmail := issue3Email(t, "member@example.com")

	seedIssue3User(t, h, adminEmail, "Admin", "admin", "active", issue3Password)
	memberID := seedIssue3User(t, h, memberEmail, "Member", "member", "active", issue3Password)

	admin := h.AuthedClient(loginViaPassword(t, h, adminEmail, issue3Password).AccessToken)
	if _, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    memberEmail,
		Password: issue3Password,
	})); err != nil {
		t.Fatalf("member login before deactivation: %v", err)
	}

	if _, err := admin.DeactivateUser(ctx, connect.NewRequest(&identitypb.DeactivateUserRequest{
		UserId: memberID,
		Reason: "end-to-end test",
	})); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}

	_, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    memberEmail,
		Password: issue3Password,
	}))
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("login after deactivation code = %v, want FailedPrecondition (err=%v)", got, err)
	}
}

func TestAdmin_ResetUserPassword_TempPassword(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()
	adminEmail := issue3Email(t, "admin@example.com")
	memberEmail := issue3Email(t, "member@example.com")

	seedIssue3User(t, h, adminEmail, "Admin", "admin", "active", issue3Password)
	memberID := seedIssue3User(t, h, memberEmail, "Member", "member", "active", issue3Password)

	admin := h.AuthedClient(loginViaPassword(t, h, adminEmail, issue3Password).AccessToken)
	reset, err := admin.ResetUserPassword(ctx, connect.NewRequest(&identitypb.ResetUserPasswordRequest{
		UserId:               memberID,
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
		Email:    memberEmail,
		Password: reset.Msg.TemporaryPassword,
	}))
	if err != nil {
		t.Fatalf("login with temporary password: %v", err)
	}
	if login.Msg.GetUser().GetId() != memberID {
		t.Fatalf("temp-password login user id = %q, want %q", login.Msg.GetUser().GetId(), memberID)
	}

	_, err = h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    memberEmail,
		Password: issue3Password,
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("old password after temp reset code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

func TestAdmin_ResetUserPassword_ResetToken(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()
	adminEmail := issue3Email(t, "admin@example.com")
	memberEmail := issue3Email(t, "member@example.com")

	seedIssue3User(t, h, adminEmail, "Admin", "admin", "active", issue3Password)
	memberID := seedIssue3User(t, h, memberEmail, "Member", "member", "active", issue3Password)

	admin := h.AuthedClient(loginViaPassword(t, h, adminEmail, issue3Password).AccessToken)
	reset, err := admin.ResetUserPassword(ctx, connect.NewRequest(&identitypb.ResetUserPasswordRequest{
		UserId:               memberID,
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
		Email:    memberEmail,
		Password: issue3Password,
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
		Email:    memberEmail,
		Password: "Reset!Pass42",
	})); err != nil {
		t.Fatalf("login with reset password: %v", err)
	}

	_, err = h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    memberEmail,
		Password: issue3Password,
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("old password after ConfirmPasswordReset code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

func TestAdmin_NonAdminDenied(t *testing.T) {
	t.Parallel()

	h := StartIssue3Server(t)
	ctx := context.Background()
	targetEmail := issue3Email(t, "target@example.com")
	adminEmail := issue3Email(t, "admin@example.com")
	memberEmail := issue3Email(t, "member@example.com")
	newEmail := issue3Email(t, "new@example.com")
	createEmail := issue3Email(t, "create@example.com")

	targetID := seedIssue3User(t, h, targetEmail, "Target", "member", "active", issue3Password)
	seedIssue3User(t, h, adminEmail, "Admin", "admin", "active", issue3Password)
	seedIssue3User(t, h, memberEmail, "Member", "member", "active", issue3Password)

	member := h.AuthedClient(loginViaPassword(t, h, memberEmail, issue3Password).AccessToken)

	cases := []struct {
		name string
		call func() error
	}{
		{
			name: "InviteUser",
			call: func() error {
				_, err := member.InviteUser(ctx, connect.NewRequest(&identitypb.InviteUserRequest{
					Email: newEmail,
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
				_, err := member.GetUser(ctx, connect.NewRequest(&identitypb.GetUserRequest{UserId: targetID}))
				return err
			},
		},
		{
			name: "UpdateUser",
			call: func() error {
				_, err := member.UpdateUser(ctx, connect.NewRequest(&identitypb.UpdateUserRequest{
					UserId: targetID,
					Name:   "Updated",
				}))
				return err
			},
		},
		{
			name: "DeactivateUser",
			call: func() error {
				_, err := member.DeactivateUser(ctx, connect.NewRequest(&identitypb.DeactivateUserRequest{
					UserId: targetID,
					Reason: "test",
				}))
				return err
			},
		},
		{
			name: "ReactivateUser",
			call: func() error {
				_, err := member.ReactivateUser(ctx, connect.NewRequest(&identitypb.ReactivateUserRequest{
					UserId: targetID,
				}))
				return err
			},
		},
		{
			name: "ResetUserPassword",
			call: func() error {
				_, err := member.ResetUserPassword(ctx, connect.NewRequest(&identitypb.ResetUserPasswordRequest{
					UserId:               targetID,
					GenerateTempPassword: true,
				}))
				return err
			},
		},
		{
			name: "SetUserQuota",
			call: func() error {
				_, err := member.SetUserQuota(ctx, connect.NewRequest(&identitypb.SetUserQuotaRequest{
					UserId:     targetID,
					QuotaBytes: 1024,
				}))
				return err
			},
		},
		{
			name: "CreateUser",
			call: func() error {
				_, err := member.CreateUser(ctx, connect.NewRequest(&identitypb.CreateUserRequest{
					Email: createEmail,
					Role:  "member",
				}))
				return err
			},
		},
		{
			name: "DeleteUser",
			call: func() error {
				_, err := member.DeleteUser(ctx, connect.NewRequest(&identitypb.DeleteUserRequest{
					UserId: targetID,
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
