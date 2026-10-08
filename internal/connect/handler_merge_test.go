package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
)

func TestMergeAccounts_Handler(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Unauthenticated.
	_, err := h.client.MergeAccounts(ctx, connect.NewRequest(&identitypb.MergeAccountsRequest{
		OtherIdentifier: "bob", OtherPassword: strongPW,
	}))
	if connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no caller: want Unauthenticated, got %v: %v", connectCodeOf(err), err)
	}

	// Off by default (GATEWAY_ACCOUNT_MERGE_ENABLED).
	_, err = h.client.MergeAccounts(ctx, authedReq(connect.NewRequest(&identitypb.MergeAccountsRequest{
		OtherIdentifier: "bob", OtherPassword: strongPW,
	}), "user-1"))
	if connectCodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("disabled: want FailedPrecondition, got %v: %v", connectCodeOf(err), err)
	}
}

func TestMergeUsers_Handler_AdminOnly(t *testing.T) {
	h := newHarness(t)
	h.db.addUser("member-1", "member@e.com", "Member", "member", "active")
	_, err := h.client.MergeUsers(context.Background(), authedReq(connect.NewRequest(&identitypb.MergeUsersRequest{
		SurvivorUserId: "a", OtherUserId: "b",
	}), "member-1"))
	if err == nil {
		t.Fatal("a member must not merge accounts")
	}
}
