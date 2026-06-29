package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/oauth"
)

func TestLinkedIdentityHandlers_AuthRequired(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.ListLinkedIdentities(ctx, connect.NewRequest(&identitypb.ListLinkedIdentitiesRequest{})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("ListLinkedIdentities unauth = %v, want Unauthenticated", connectCodeOf(err))
	}
	if _, err := h.client.LinkIdentity(ctx, connect.NewRequest(&identitypb.LinkIdentityRequest{Provider: "google", Code: "c", RedirectUri: "https://app/cb"})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("LinkIdentity unauth = %v, want Unauthenticated", connectCodeOf(err))
	}
	if _, err := h.client.UnlinkIdentity(ctx, connect.NewRequest(&identitypb.UnlinkIdentityRequest{Provider: "google", ProviderUserId: "g-1"})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("UnlinkIdentity unauth = %v, want Unauthenticated", connectCodeOf(err))
	}
}

func TestLinkedIdentityHandlers_LinkListUnlink(t *testing.T) {
	registry := oauth.NewRegistry()
	registry.Register("google", connectOAuthExchanger{})
	h := newHarnessWithOAuthRegistry(t, registry)
	ctx := context.Background()

	// Authenticated user with a password (so the linked provider is never
	// the last credential and unlink is allowed).
	u := h.repo.seedUser(&service.User{Email: "cap@e.com", Status: "active", Role: "member", PasswordHash: "hash"})

	linkResp, err := h.client.LinkIdentity(ctx, authedReq(connect.NewRequest(&identitypb.LinkIdentityRequest{
		Provider: "google", Code: "auth-code", RedirectUri: "https://app/cb",
	}), u.ID))
	if err != nil {
		t.Fatalf("LinkIdentity: %v", err)
	}
	if linkResp.Msg.Identity.GetProvider() != "google" || linkResp.Msg.Identity.GetProviderUserId() != "connect-user" {
		t.Fatalf("unexpected linked identity: %+v", linkResp.Msg.Identity)
	}

	listResp, err := h.client.ListLinkedIdentities(ctx, authedReq(connect.NewRequest(&identitypb.ListLinkedIdentitiesRequest{}), u.ID))
	if err != nil {
		t.Fatalf("ListLinkedIdentities: %v", err)
	}
	if len(listResp.Msg.Identities) != 1 {
		t.Fatalf("ListLinkedIdentities len = %d, want 1", len(listResp.Msg.Identities))
	}

	// Re-linking the same provider identity is rejected.
	if _, err := h.client.LinkIdentity(ctx, authedReq(connect.NewRequest(&identitypb.LinkIdentityRequest{
		Provider: "google", Code: "auth-code", RedirectUri: "https://app/cb",
	}), u.ID)); connectCodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("re-link = %v, want AlreadyExists", connectCodeOf(err))
	}

	if _, err := h.client.UnlinkIdentity(ctx, authedReq(connect.NewRequest(&identitypb.UnlinkIdentityRequest{
		Provider: "google", ProviderUserId: "connect-user",
	}), u.ID)); err != nil {
		t.Fatalf("UnlinkIdentity: %v", err)
	}

	listResp, err = h.client.ListLinkedIdentities(ctx, authedReq(connect.NewRequest(&identitypb.ListLinkedIdentitiesRequest{}), u.ID))
	if err != nil {
		t.Fatalf("ListLinkedIdentities after unlink: %v", err)
	}
	if len(listResp.Msg.Identities) != 0 {
		t.Fatalf("ListLinkedIdentities after unlink len = %d, want 0", len(listResp.Msg.Identities))
	}
}

func TestLinkedIdentityHandlers_UnlinkLastCredentialBlocked(t *testing.T) {
	registry := oauth.NewRegistry()
	registry.Register("google", connectOAuthExchanger{})
	h := newHarnessWithOAuthRegistry(t, registry)
	ctx := context.Background()

	// User with NO password and only the single linked provider: unlink is a
	// FailedPrecondition (would remove the last sign-in credential).
	u := h.repo.seedUser(&service.User{Email: "nopw@e.com", Status: "active", Role: "member"})

	if _, err := h.client.LinkIdentity(ctx, authedReq(connect.NewRequest(&identitypb.LinkIdentityRequest{
		Provider: "google", Code: "auth-code", RedirectUri: "https://app/cb",
	}), u.ID)); err != nil {
		t.Fatalf("LinkIdentity: %v", err)
	}

	if _, err := h.client.UnlinkIdentity(ctx, authedReq(connect.NewRequest(&identitypb.UnlinkIdentityRequest{
		Provider: "google", ProviderUserId: "connect-user",
	}), u.ID)); connectCodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("unlink last credential = %v, want FailedPrecondition", connectCodeOf(err))
	}

	// Unlinking a non-existent link is NotFound.
	if _, err := h.client.UnlinkIdentity(ctx, authedReq(connect.NewRequest(&identitypb.UnlinkIdentityRequest{
		Provider: "google", ProviderUserId: "nope",
	}), u.ID)); connectCodeOf(err) != connect.CodeNotFound {
		t.Fatalf("unlink missing = %v, want NotFound", connectCodeOf(err))
	}
}
