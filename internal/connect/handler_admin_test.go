package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// TestDeleteUser_HardDeletes drives the DeleteUser RPC end to end: an
// admin deletes a user, the Repository cascade runs, and the same email
// becomes reusable (a follow-up InviteUser with the same address
// succeeds). The connect harness uses a separate fakeRepo (cascade) and
// fakeDB (admin authorization), so the target is seeded in both.
func TestDeleteUser_HardDeletes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.db.addUser("admin-1", "admin@e.com", "Admin", "admin", "active")
	target := h.repo.seedUser(&service.User{Email: "victim@e.com", Status: "active", Role: "member"})
	// Seed a refresh token to prove the cascade reaches user-owned rows.
	if _, err := h.repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
		TokenHash: "rt-victim", UserID: target.ID, ExpiresAt: 9_000_000_000_000,
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	if _, err := h.client.DeleteUser(ctx, authedReq(connect.NewRequest(&identitypb.DeleteUserRequest{
		UserId: target.ID,
	}), "admin-1")); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	if u, _ := h.repo.GetUser(ctx, target.ID); u != nil {
		t.Fatalf("user must be deleted from repo, got %#v", u)
	}
	if rec, _ := h.repo.FindRefreshTokenByHashIncludingConsumed(ctx, "rt-victim"); rec != nil {
		t.Fatalf("refresh token must be cascaded, got %#v", rec)
	}

	// Email reusable: a fresh InviteUser with the same address succeeds.
	inv, err := h.client.InviteUser(ctx, authedReq(connect.NewRequest(&identitypb.InviteUserRequest{
		Email: "victim@e.com", Name: "Victim Reborn", Role: "member",
	}), "admin-1"))
	if err != nil {
		t.Fatalf("re-invite with reused email: %v", err)
	}
	if inv.Msg.User == nil || inv.Msg.User.Id == "" {
		t.Fatalf("re-invite result: %+v", inv.Msg)
	}
}

func TestDeleteUser_NotFound(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("admin-1", "admin@e.com", "Admin", "admin", "active")

	_, err := h.client.DeleteUser(ctx, authedReq(connect.NewRequest(&identitypb.DeleteUserRequest{
		UserId: "ghost",
	}), "admin-1"))
	if err == nil {
		t.Fatal("expected error deleting non-existent user")
	}
	if connectCodeOf(err) != connect.CodeNotFound {
		t.Fatalf("expected CodeNotFound, got %v: %v", connectCodeOf(err), err)
	}
}
