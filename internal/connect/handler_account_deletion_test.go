package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

func TestAccountDeletionHandlers_AuthRequired(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.DeleteMyAccount(ctx, connect.NewRequest(&identitypb.DeleteMyAccountRequest{Reason: "x"})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("DeleteMyAccount unauth = %v, want Unauthenticated", connectCodeOf(err))
	}
	if _, err := h.client.CancelAccountDeletion(ctx, connect.NewRequest(&identitypb.CancelAccountDeletionRequest{})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("CancelAccountDeletion unauth = %v, want Unauthenticated", connectCodeOf(err))
	}
}

func TestAccountDeletionHandlers_ScheduleThenCancel(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	u := h.repo.seedUser(&service.User{Email: "self@e.com", Status: service.StatusActive, Role: "member", PasswordHash: "hash"})

	delResp, err := h.client.DeleteMyAccount(ctx, authedReq(connect.NewRequest(&identitypb.DeleteMyAccountRequest{
		Reason: "cleaning up",
	}), u.ID))
	if err != nil {
		t.Fatalf("DeleteMyAccount: %v", err)
	}
	if delResp.Msg.GetDeletionScheduledAtMs() <= 0 {
		t.Fatalf("deletion_scheduled_at_ms = %d, want > 0", delResp.Msg.GetDeletionScheduledAtMs())
	}

	// The account is now pending deletion in the store.
	got, _ := h.repo.GetUser(ctx, u.ID)
	if got == nil || got.Status != service.StatusPendingDeletion {
		t.Fatalf("status after DeleteMyAccount = %#v, want pending_deletion", got)
	}

	// Cancelling reports the account back to ACTIVE via the proto enum.
	cancelResp, err := h.client.CancelAccountDeletion(ctx, authedReq(connect.NewRequest(&identitypb.CancelAccountDeletionRequest{}), u.ID))
	if err != nil {
		t.Fatalf("CancelAccountDeletion: %v", err)
	}
	if cancelResp.Msg.GetStatus() != identitypb.UserStatus_USER_STATUS_ACTIVE {
		t.Fatalf("cancel status = %v, want ACTIVE", cancelResp.Msg.GetStatus())
	}
	got, _ = h.repo.GetUser(ctx, u.ID)
	if got.Status != service.StatusActive || got.DeletionScheduledAtMs != 0 {
		t.Fatalf("after cancel: status=%q scheduled=%d", got.Status, got.DeletionScheduledAtMs)
	}
}
