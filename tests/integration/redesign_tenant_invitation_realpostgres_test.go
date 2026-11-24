//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// readInvitation reads the invitation token names with no session.
func readInvitation(t *testing.T, h *RedesignHarness, token string) *identitypb.GetTenantInvitationResponse {
	t.Helper()
	resp, err := h.Client.GetTenantInvitation(context.Background(), connect.NewRequest(&identitypb.GetTenantInvitationRequest{Token: token}))
	if err != nil {
		t.Fatalf("GetTenantInvitation: %v", err)
	}
	return resp.Msg
}

// TestRedesign_TenantInvitation_ReadByItsTokenWithoutASession drives the
// invitation link's read against a real Postgres: the mailed token describes
// the invitation with no session, says whether the address has an account
// once it has one, is still accepted afterwards, and reads accepted once it
// is; a token no invitation has is NOT_FOUND.
func TestRedesign_TenantInvitation_ReadByItsTokenWithoutASession(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	owner := signupOwner(t, h, "invitation-read-owner")
	inviter, err := h.Stores.users.WithProject(h.ProjectID).GetUser(ctx, owner.userID)
	if err != nil || inviter == nil {
		t.Fatalf("inviter: %v %v", inviter, err)
	}
	invitee := fmt.Sprintf("read-%d@example-corp.com", time.Now().UnixNano())
	_, token := inviteFrom(t, h, owner, invitee)

	got := readInvitation(t, h, token)
	if got.GetTenantId() != owner.tenantID || got.GetTenantName() != "invitation-read-owner tenant" ||
		got.GetInviterName() != inviter.Name || got.GetInviterEmail() != inviter.Email ||
		got.GetEmail() != invitee || got.GetRole() != service.RoleMember ||
		got.GetStatus() != service.InvitationStatusPending || got.GetAccountExists() ||
		got.GetExpiresAtMs() <= time.Now().UnixMilli() {
		t.Fatalf("invitation = %+v", got)
	}

	member := signupVerifiedUser(t, h, invitee)
	if got := readInvitation(t, h, token); !got.GetAccountExists() || got.GetStatus() != service.InvitationStatusPending {
		t.Fatalf("after the address signed up: %+v, want account_exists and still pending", got)
	}
	if _, err := member.client.AcceptTenantInvitation(ctx, connect.NewRequest(&identitypb.AcceptTenantInvitationRequest{Token: token})); err != nil {
		t.Fatalf("AcceptTenantInvitation after reading: %v", err)
	}
	if got := readInvitation(t, h, token); got.GetStatus() != service.InvitationStatusAccepted {
		t.Fatalf("status after accepting = %q, want accepted", got.GetStatus())
	}

	_, err = h.Client.GetTenantInvitation(ctx, connect.NewRequest(&identitypb.GetTenantInvitationRequest{Token: "0123456789abcdef"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("unknown token = %v, want NotFound", err)
	}
}
