package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// seedManagedChildViaRPC drives the real parent-creates-child RPC so the
// guardian edge, the consent record and the child account exist exactly as
// production creates them, and returns the child's user id.
func seedManagedChildViaRPC(ctx context.Context, t *testing.T, h *testHarness, adultID, username string) string {
	t.Helper()
	res, err := h.client.CreateManagedChildAccount(ctx,
		authedReq(connect.NewRequest(managedChildRequest(username)), adultID))
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}
	return res.Msg.GetChild().GetId()
}

// managementCall is one guardian-management RPC, parameterized by caller,
// target and step-up password, so the shared guard can be tested across the
// whole surface rather than once per RPC.
type managementCall struct {
	name string
	call func(h *testHarness, caller, child, stepUp string) error
}

func managementCalls() []managementCall {
	ctx := context.Background()
	return []managementCall{
		{"GetManagedChildProfile", func(h *testHarness, c, ch, su string) error {
			_, err := h.client.GetManagedChildProfile(ctx, authedReq(connect.NewRequest(
				&identitypb.GetManagedChildProfileRequest{ChildUserId: ch, StepUpPassword: su},
			), c))
			return err
		}},
		{"SetManagedChildPassword", func(h *testHarness, c, ch, su string) error {
			_, err := h.client.SetManagedChildPassword(ctx, authedReq(connect.NewRequest(
				&identitypb.SetManagedChildPasswordRequest{ChildUserId: ch, NewPassword: "An0ther!Str0ng", StepUpPassword: su},
			), c))
			return err
		}},
		{"SetManagedChildUsername", func(h *testHarness, c, ch, su string) error {
			_, err := h.client.SetManagedChildUsername(ctx, authedReq(connect.NewRequest(
				&identitypb.SetManagedChildUsernameRequest{ChildUserId: ch, Username: "kid.renamed", StepUpPassword: su},
			), c))
			return err
		}},
		{"RevokeManagedChildSessions", func(h *testHarness, c, ch, su string) error {
			_, err := h.client.RevokeManagedChildSessions(ctx, authedReq(connect.NewRequest(
				&identitypb.RevokeManagedChildSessionsRequest{ChildUserId: ch, StepUpPassword: su},
			), c))
			return err
		}},
		{"DeactivateManagedChildAccount", func(h *testHarness, c, ch, su string) error {
			_, err := h.client.DeactivateManagedChildAccount(ctx, authedReq(connect.NewRequest(
				&identitypb.DeactivateManagedChildAccountRequest{ChildUserId: ch, Reason: "lost tablet", StepUpPassword: su},
			), c))
			return err
		}},
		{"ReactivateManagedChildAccount", func(h *testHarness, c, ch, su string) error {
			_, err := h.client.ReactivateManagedChildAccount(ctx, authedReq(connect.NewRequest(
				&identitypb.ReactivateManagedChildAccountRequest{ChildUserId: ch, StepUpPassword: su},
			), c))
			return err
		}},
		{"DeleteManagedChildAccount", func(h *testHarness, c, ch, su string) error {
			_, err := h.client.DeleteManagedChildAccount(ctx, authedReq(connect.NewRequest(
				&identitypb.DeleteManagedChildAccountRequest{ChildUserId: ch, StepUpPassword: su},
			), c))
			return err
		}},
	}
}

// TestManagementRequests_CarryNoCallerIdentity pins the API contract across
// the whole management surface: the acting guardian is the session user, so
// no request message may carry a field a client could use to assert who is
// acting. Every request DOES carry step_up_password — the second mandatory
// check — so its absence would be a contract regression too.
func TestManagementRequests_CarryNoCallerIdentity(t *testing.T) {
	descriptors := []protoreflect.MessageDescriptor{
		(&identitypb.GetManagedChildProfileRequest{}).ProtoReflect().Descriptor(),
		(&identitypb.SetManagedChildPasswordRequest{}).ProtoReflect().Descriptor(),
		(&identitypb.SetManagedChildUsernameRequest{}).ProtoReflect().Descriptor(),
		(&identitypb.RevokeManagedChildSessionsRequest{}).ProtoReflect().Descriptor(),
		(&identitypb.DeactivateManagedChildAccountRequest{}).ProtoReflect().Descriptor(),
		(&identitypb.ReactivateManagedChildAccountRequest{}).ProtoReflect().Descriptor(),
		(&identitypb.DeleteManagedChildAccountRequest{}).ProtoReflect().Descriptor(),
	}
	forbidden := map[string]bool{
		"guardian_user_id": true, "caller_user_id": true, "parent_user_id": true,
		"actor_user_id": true, "user_id": true,
	}
	for _, md := range descriptors {
		hasStepUp := false
		for i := 0; i < md.Fields().Len(); i++ {
			name := string(md.Fields().Get(i).Name())
			if forbidden[name] {
				t.Fatalf("%s must not carry a caller identity field, found %q", md.Name(), name)
			}
			if name == "step_up_password" {
				hasStepUp = true
			}
		}
		if !hasStepUp {
			t.Fatalf("%s must carry step_up_password", md.Name())
		}
	}
}

// TestHandler_ManagementSurface_Guard proves the guard is applied at the
// handler boundary for every operation: unauthenticated callers, callers
// with no guardian edge, and callers who fail step-up are all refused, with
// the codes the wire contract promises.
func TestHandler_ManagementSurface_Guard(t *testing.T) {
	ctx := context.Background()
	for _, op := range managementCalls() {
		t.Run(op.name, func(t *testing.T) {
			t.Run("unauthenticated", func(t *testing.T) {
				h := newHarness(t)
				adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
				child := seedManagedChildViaRPC(ctx, t, h, adult, "kid.one")
				// No session header at all.
				err := op.call(h, "", child, consentTestPassword)
				if got := connectCodeOf(err); got != connect.CodeUnauthenticated {
					t.Fatalf("code = %v, want Unauthenticated", got)
				}
			})

			t.Run("not a guardian", func(t *testing.T) {
				h := newHarness(t)
				adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
				stranger := seedConsentAdult(ctx, t, h, "stranger@example.com", true)
				child := seedManagedChildViaRPC(ctx, t, h, adult, "kid.one")

				err := op.call(h, stranger, child, consentTestPassword)
				if got := connectCodeOf(err); got != connect.CodePermissionDenied {
					t.Fatalf("code = %v, want PermissionDenied", got)
				}
			})

			t.Run("step-up fails", func(t *testing.T) {
				h := newHarness(t)
				adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
				child := seedManagedChildViaRPC(ctx, t, h, adult, "kid.one")

				err := op.call(h, adult, child, "not-the-password")
				if got := connectCodeOf(err); got != connect.CodeUnauthenticated {
					t.Fatalf("code = %v, want Unauthenticated", got)
				}
			})
		})
	}
}

// TestHandler_ManagementDenial_DisclosesNothing pins that a caller with no
// edge cannot tell a real child account from an invented id.
func TestHandler_ManagementDenial_DisclosesNothing(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
	stranger := seedConsentAdult(ctx, t, h, "stranger@example.com", true)
	child := seedManagedChildViaRPC(ctx, t, h, adult, "kid.one")

	call := func(childID string) error {
		_, err := h.client.GetManagedChildProfile(ctx, authedReq(connect.NewRequest(
			&identitypb.GetManagedChildProfileRequest{ChildUserId: childID, StepUpPassword: consentTestPassword},
		), stranger))
		return err
	}
	errExisting, errMissing := call(child), call("no-such-child")
	if connectCodeOf(errExisting) != connect.CodePermissionDenied || connectCodeOf(errMissing) != connect.CodePermissionDenied {
		t.Fatalf("codes = %v / %v, want PermissionDenied for both", connectCodeOf(errExisting), connectCodeOf(errMissing))
	}
	if errExisting.Error() != errMissing.Error() {
		t.Fatalf("denial must be account-agnostic: %q vs %q", errExisting, errMissing)
	}
}

// TestHandler_ManagementSurface_HappyPath walks the operations a parent
// actually performs, over the wire, in the order a parent performs them.
func TestHandler_ManagementSurface_HappyPath(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
	child := seedManagedChildViaRPC(ctx, t, h, adult, "kid.one")

	// View.
	view, err := h.client.GetManagedChildProfile(ctx, authedReq(connect.NewRequest(
		&identitypb.GetManagedChildProfileRequest{ChildUserId: child, StepUpPassword: consentTestPassword},
	), adult))
	if err != nil {
		t.Fatalf("GetManagedChildProfile: %v", err)
	}
	if view.Msg.GetChild().GetId() != child || view.Msg.GetChild().GetUsername() != "kid.one" {
		t.Fatalf("child = %+v, want the managed account", view.Msg.GetChild())
	}

	// Rename.
	renamed, err := h.client.SetManagedChildUsername(ctx, authedReq(connect.NewRequest(
		&identitypb.SetManagedChildUsernameRequest{ChildUserId: child, Username: "kid.two", StepUpPassword: consentTestPassword},
	), adult))
	if err != nil {
		t.Fatalf("SetManagedChildUsername: %v", err)
	}
	if renamed.Msg.GetChild().GetUsername() != "kid.two" {
		t.Fatalf("username = %q, want kid.two", renamed.Msg.GetChild().GetUsername())
	}

	// Reset the password.
	if _, err := h.client.SetManagedChildPassword(ctx, authedReq(connect.NewRequest(
		&identitypb.SetManagedChildPasswordRequest{
			ChildUserId: child, NewPassword: "An0ther!Str0ng", StepUpPassword: consentTestPassword,
		},
	), adult)); err != nil {
		t.Fatalf("SetManagedChildPassword: %v", err)
	}

	// Cut the sessions.
	if _, err := h.client.RevokeManagedChildSessions(ctx, authedReq(connect.NewRequest(
		&identitypb.RevokeManagedChildSessionsRequest{ChildUserId: child, StepUpPassword: consentTestPassword},
	), adult)); err != nil {
		t.Fatalf("RevokeManagedChildSessions: %v", err)
	}

	// Deactivate, then reactivate.
	if _, err := h.client.DeactivateManagedChildAccount(ctx, authedReq(connect.NewRequest(
		&identitypb.DeactivateManagedChildAccountRequest{
			ChildUserId: child, Reason: "lost tablet", StepUpPassword: consentTestPassword,
		},
	), adult)); err != nil {
		t.Fatalf("DeactivateManagedChildAccount: %v", err)
	}
	stored, _ := h.repo.GetUser(ctx, child)
	if stored.Status != service.StatusDeactivated {
		t.Fatalf("status = %q, want %q", stored.Status, service.StatusDeactivated)
	}
	if _, err := h.client.ReactivateManagedChildAccount(ctx, authedReq(connect.NewRequest(
		&identitypb.ReactivateManagedChildAccountRequest{ChildUserId: child, StepUpPassword: consentTestPassword},
	), adult)); err != nil {
		t.Fatalf("ReactivateManagedChildAccount: %v", err)
	}
	stored, _ = h.repo.GetUser(ctx, child)
	if stored.Status != service.StatusActive {
		t.Fatalf("status = %q, want %q", stored.Status, service.StatusActive)
	}

	// Erase. The account goes; the consent record stays.
	if _, err := h.client.DeleteManagedChildAccount(ctx, authedReq(connect.NewRequest(
		&identitypb.DeleteManagedChildAccountRequest{ChildUserId: child, StepUpPassword: consentTestPassword},
	), adult)); err != nil {
		t.Fatalf("DeleteManagedChildAccount: %v", err)
	}
	if u, _ := h.repo.GetUser(ctx, child); u != nil {
		t.Fatal("the child account must be erased")
	}
	if rec, err := h.repo.GetActiveParentalConsentForChild(ctx, child); err != nil || rec == nil {
		t.Fatalf("the consent record must survive the erasure: %v %#v", err, rec)
	}
}

// TestHandler_ManagementSurface_ErrorCodes pins the Connect codes the wire
// contract promises for the refusals a client has to branch on, so a mapping
// regression is caught at the boundary rather than by a client.
func TestHandler_ManagementSurface_ErrorCodes(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
	child := seedManagedChildViaRPC(ctx, t, h, adult, "kid.one")

	t.Run("missing child id is InvalidArgument", func(t *testing.T) {
		_, err := h.client.GetManagedChildProfile(ctx, authedReq(connect.NewRequest(
			&identitypb.GetManagedChildProfileRequest{ChildUserId: "  ", StepUpPassword: consentTestPassword},
		), adult))
		if got := connectCodeOf(err); got != connect.CodeInvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", got)
		}
	})

	t.Run("weak new password is InvalidArgument", func(t *testing.T) {
		_, err := h.client.SetManagedChildPassword(ctx, authedReq(connect.NewRequest(
			&identitypb.SetManagedChildPasswordRequest{
				ChildUserId: child, NewPassword: "short", StepUpPassword: consentTestPassword,
			},
		), adult))
		if got := connectCodeOf(err); got != connect.CodeInvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", got)
		}
	})

	t.Run("taken username is AlreadyExists", func(t *testing.T) {
		other := seedManagedChildViaRPC(ctx, t, h, adult, "kid.two")
		_ = other
		_, err := h.client.SetManagedChildUsername(ctx, authedReq(connect.NewRequest(
			&identitypb.SetManagedChildUsernameRequest{
				ChildUserId: child, Username: "kid.two", StepUpPassword: consentTestPassword,
			},
		), adult))
		if got := connectCodeOf(err); got != connect.CodeAlreadyExists {
			t.Fatalf("code = %v, want AlreadyExists", got)
		}
	})

	t.Run("reactivating an account awaiting consent is FailedPrecondition", func(t *testing.T) {
		gated := seedManagedChildViaRPC(ctx, t, h, adult, "kid.three")
		if err := h.repo.UpdateUser(ctx, gated, map[string]any{"status": service.StatusPendingParentalConsent}); err != nil {
			t.Fatalf("gate the child: %v", err)
		}
		_, err := h.client.ReactivateManagedChildAccount(ctx, authedReq(connect.NewRequest(
			&identitypb.ReactivateManagedChildAccountRequest{ChildUserId: gated, StepUpPassword: consentTestPassword},
		), adult))
		if got := connectCodeOf(err); got != connect.CodeFailedPrecondition {
			t.Fatalf("code = %v, want FailedPrecondition", got)
		}
	})
}
