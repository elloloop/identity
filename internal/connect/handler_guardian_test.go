package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// grantConsentViaRPC drives the full grant path so the guardian edge is
// created exactly as production creates it.
func grantConsentViaRPC(t *testing.T, h *testHarness, adultID, childID string) {
	t.Helper()
	req := connect.NewRequest(&identitypb.GrantParentalConsentRequest{
		ChildUserId:    childID,
		PolicyVersion:  consentTestPolicy,
		StepUpPassword: consentTestPassword,
	})
	authedReq(req, adultID)
	if _, err := h.client.GrantParentalConsent(context.Background(), req); err != nil {
		t.Fatalf("GrantParentalConsent: %v", err)
	}
}

// TestListManagedChildrenRequest_CarriesNoUserID pins the API contract that
// the guardian is always the session user: the request message must never
// grow a field a client could use to steer the query at another account.
func TestListManagedChildrenRequest_CarriesNoUserID(t *testing.T) {
	md := (&identitypb.ListManagedChildrenRequest{}).ProtoReflect().Descriptor()
	if md.Fields().Len() != 0 {
		var names []string
		for i := 0; i < md.Fields().Len(); i++ {
			names = append(names, string(md.Fields().Get(i).Name()))
		}
		t.Fatalf("ListManagedChildrenRequest must have no fields, got %v", names)
	}
}

func TestHandler_ListManagedChildren(t *testing.T) {
	h := newHarness(t)
	adult := seedConsentAdult(t, h, "adult@example.com", true)
	child1 := seedConsentChild(t, h, "child1@example.com")
	child2 := seedConsentChild(t, h, "child2@example.com")

	// No edges yet: empty list.
	req := authedReq(connect.NewRequest(&identitypb.ListManagedChildrenRequest{}), adult)
	res, err := h.client.ListManagedChildren(context.Background(), req)
	if err != nil {
		t.Fatalf("ListManagedChildren (empty): %v", err)
	}
	if len(res.Msg.GetChildren()) != 0 {
		t.Fatalf("children = %d, want 0", len(res.Msg.GetChildren()))
	}

	// Granting consent creates the edges; both children list.
	grantConsentViaRPC(t, h, adult, child1)
	grantConsentViaRPC(t, h, adult, child2)

	res, err = h.client.ListManagedChildren(context.Background(), authedReq(connect.NewRequest(&identitypb.ListManagedChildrenRequest{}), adult))
	if err != nil {
		t.Fatalf("ListManagedChildren: %v", err)
	}
	got := map[string]bool{}
	for _, c := range res.Msg.GetChildren() {
		got[c.GetId()] = true
	}
	if len(got) != 2 || !got[child1] || !got[child2] {
		t.Fatalf("children = %v, want {%s, %s}", got, child1, child2)
	}

	// Another account sees none of them.
	stranger := seedConsentAdult(t, h, "stranger@example.com", true)
	res, err = h.client.ListManagedChildren(context.Background(), authedReq(connect.NewRequest(&identitypb.ListManagedChildrenRequest{}), stranger))
	if err != nil {
		t.Fatalf("ListManagedChildren (stranger): %v", err)
	}
	if len(res.Msg.GetChildren()) != 0 {
		t.Fatalf("stranger children = %d, want 0", len(res.Msg.GetChildren()))
	}
}

func TestHandler_ListManagedChildren_RequiresAuth(t *testing.T) {
	h := newHarness(t)
	_, err := h.client.ListManagedChildren(context.Background(), connect.NewRequest(&identitypb.ListManagedChildrenRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

func TestHandler_GetGuardians(t *testing.T) {
	h := newHarness(t)
	adult := seedConsentAdult(t, h, "adult@example.com", true)
	child := seedConsentChild(t, h, "child@example.com")
	grantConsentViaRPC(t, h, adult, child)

	// The guardian may list.
	req := authedReq(connect.NewRequest(&identitypb.GetGuardiansRequest{ChildUserId: child}), adult)
	res, err := h.client.GetGuardians(context.Background(), req)
	if err != nil {
		t.Fatalf("GetGuardians (guardian): %v", err)
	}
	if len(res.Msg.GetGuardians()) != 1 || res.Msg.GetGuardians()[0].GetId() != adult {
		t.Fatalf("guardians = %v, want [%s]", res.Msg.GetGuardians(), adult)
	}

	// A project admin (role=admin on the caller's own account) may list
	// without holding an edge.
	adminID, err := h.repo.CreateUser(context.Background(), &service.User{
		Email: "admin@example.com", Status: "active", Role: "admin",
	})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	res, err = h.client.GetGuardians(context.Background(), authedReq(connect.NewRequest(&identitypb.GetGuardiansRequest{ChildUserId: child}), adminID))
	if err != nil {
		t.Fatalf("GetGuardians (admin): %v", err)
	}
	if len(res.Msg.GetGuardians()) != 1 {
		t.Fatalf("admin guardians = %d, want 1", len(res.Msg.GetGuardians()))
	}
}

// TestHandler_GetGuardians_NoExistenceDisclosure pins the account-agnostic
// denial: a non-guardian non-admin gets the identical PERMISSION_DENIED for
// an existing and a nonexistent child.
func TestHandler_GetGuardians_NoExistenceDisclosure(t *testing.T) {
	h := newHarness(t)
	adult := seedConsentAdult(t, h, "adult@example.com", true)
	stranger := seedConsentAdult(t, h, "stranger@example.com", true)
	child := seedConsentChild(t, h, "child@example.com")
	grantConsentViaRPC(t, h, adult, child)

	_, errExisting := h.client.GetGuardians(context.Background(),
		authedReq(connect.NewRequest(&identitypb.GetGuardiansRequest{ChildUserId: child}), stranger))
	_, errMissing := h.client.GetGuardians(context.Background(),
		authedReq(connect.NewRequest(&identitypb.GetGuardiansRequest{ChildUserId: "no-such-child"}), stranger))

	if connect.CodeOf(errExisting) != connect.CodePermissionDenied {
		t.Fatalf("existing child: code = %v, want PermissionDenied", connect.CodeOf(errExisting))
	}
	if connect.CodeOf(errMissing) != connect.CodePermissionDenied {
		t.Fatalf("nonexistent child: code = %v, want PermissionDenied", connect.CodeOf(errMissing))
	}
}

func TestHandler_GetGuardians_RequiresAuth(t *testing.T) {
	h := newHarness(t)
	_, err := h.client.GetGuardians(context.Background(), connect.NewRequest(&identitypb.GetGuardiansRequest{ChildUserId: "c"}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}
