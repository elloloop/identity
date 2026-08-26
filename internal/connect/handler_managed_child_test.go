package connect

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// childDOB is a date of birth well inside the minor bands for any threshold
// the tests configure.
func childDOB() int64 { return time.Now().AddDate(-8, 0, 0).UnixMilli() }

func managedChildRequest(username string) *identitypb.CreateManagedChildAccountRequest {
	return &identitypb.CreateManagedChildAccountRequest{
		Username:       username,
		DisplayName:    "Kid One",
		DateOfBirthMs:  childDOB(),
		Password:       consentTestPassword,
		PolicyVersion:  consentTestPolicy,
		StepUpPassword: consentTestPassword,
	}
}

// TestCreateManagedChildAccountRequest_CarriesNoCallerIdentity pins the API
// contract: the creating adult is the session user, so the request message
// must never grow a field a client could use to assert who is creating (and
// therefore consenting for) the account.
func TestCreateManagedChildAccountRequest_CarriesNoCallerIdentity(t *testing.T) {
	md := (&identitypb.CreateManagedChildAccountRequest{}).ProtoReflect().Descriptor()
	forbidden := map[string]bool{
		"guardian_user_id": true, "consenting_user_id": true, "caller_user_id": true,
		"parent_user_id": true, "user_id": true, "actor_user_id": true,
	}
	for i := 0; i < md.Fields().Len(); i++ {
		if name := string(md.Fields().Get(i).Name()); forbidden[name] {
			t.Fatalf("CreateManagedChildAccountRequest must not carry a caller identity field, found %q", name)
		}
	}
}

// TestHandler_CreateManagedChildAccount_CallerIsServerDerived proves the
// guardian and the consent record's consenting_user_id come from the verified
// session header, not from anything the client can influence.
func TestHandler_CreateManagedChildAccount_CallerIsServerDerived(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
	other := seedConsentAdult(ctx, t, h, "other@example.com", true)

	req := authedReq(withClientHeaders(connect.NewRequest(managedChildRequest("kid.one"))), adult)
	res, err := h.client.CreateManagedChildAccount(ctx, req)
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}

	child := res.Msg.GetChild()
	if child.GetUsername() != "kid.one" || child.GetStatus() != identitypb.UserStatus_USER_STATUS_ACTIVE {
		t.Fatalf("child = %+v, want an active username-identified account", child)
	}
	if got := res.Msg.GetConsent().GetConsentingUserId(); got != adult {
		t.Fatalf("consenting_user_id = %q, want the session user %q", got, adult)
	}
	if res.Msg.GetConsent().GetChildUserId() != child.GetId() {
		t.Fatalf("consent child_user_id = %q, want %q", res.Msg.GetConsent().GetChildUserId(), child.GetId())
	}
	if res.Msg.GetEnrolmentToken() != "" {
		t.Fatal("the password arm must not mint an enrolment ticket")
	}

	// The edge is the caller's, not the other adult's: only the creator can
	// list the child.
	listed, err := h.client.ListManagedChildren(ctx,
		authedReq(connect.NewRequest(&identitypb.ListManagedChildrenRequest{}), other))
	if err != nil {
		t.Fatalf("ListManagedChildren (other): %v", err)
	}
	if len(listed.Msg.GetChildren()) != 0 {
		t.Fatalf("another adult must manage no children, got %d", len(listed.Msg.GetChildren()))
	}
}

func TestHandler_CreateManagedChildAccount_Unauthenticated(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	_, err := h.client.CreateManagedChildAccount(ctx,
		connect.NewRequest(managedChildRequest("kid.one")))
	if got := connectCodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", got)
	}
}

// TestHandler_CreateManagedChildAccount_StepUpAndFactorMapping pins that both
// mandatory service-side checks surface as distinct, correct Connect codes.
func TestHandler_CreateManagedChildAccount_StepUpAndFactorMapping(t *testing.T) {
	ctx := context.Background()
	t.Run("wrong step-up password", func(t *testing.T) {
		h := newHarness(t)
		adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
		msg := managedChildRequest("kid.one")
		msg.StepUpPassword = "not-the-password"

		_, err := h.client.CreateManagedChildAccount(ctx,
			authedReq(connect.NewRequest(msg), adult))
		if got := connectCodeOf(err); got != connect.CodeUnauthenticated {
			t.Fatalf("code = %v, want Unauthenticated", got)
		}
	})

	t.Run("no strong verified factor", func(t *testing.T) {
		h := newHarness(t)
		adult := seedConsentAdult(ctx, t, h, "adult@example.com", false)

		_, err := h.client.CreateManagedChildAccount(ctx,
			authedReq(connect.NewRequest(managedChildRequest("kid.one")), adult))
		if got := connectCodeOf(err); got != connect.CodeFailedPrecondition {
			t.Fatalf("code = %v, want FailedPrecondition", got)
		}
	})

	t.Run("duplicate username", func(t *testing.T) {
		h := newHarness(t)
		adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
		if _, err := h.client.CreateManagedChildAccount(ctx,
			authedReq(connect.NewRequest(managedChildRequest("kid.one")), adult)); err != nil {
			t.Fatalf("first create: %v", err)
		}

		_, err := h.client.CreateManagedChildAccount(ctx,
			authedReq(connect.NewRequest(managedChildRequest("kid.one")), adult))
		if got := connectCodeOf(err); got != connect.CodeAlreadyExists {
			t.Fatalf("code = %v, want AlreadyExists", got)
		}
	})
}

// TestHandler_CreateManagedChildAccount_NeverPendingConsent pins the
// born-active invariant across the wire: the account the RPC returns is
// ACTIVE and the stored row agrees.
func TestHandler_CreateManagedChildAccount_NeverPendingConsent(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)

	res, err := h.client.CreateManagedChildAccount(ctx,
		authedReq(connect.NewRequest(managedChildRequest("kid.one")), adult))
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}

	stored, err := h.repo.GetUser(ctx, res.Msg.GetChild().GetId())
	if err != nil || stored == nil {
		t.Fatalf("stored child: %v %#v", err, stored)
	}
	if stored.Status != service.StatusActive {
		t.Fatalf("stored status = %q, want %q", stored.Status, service.StatusActive)
	}
}

// TestHandler_PasskeyEnrolmentTicket_ResolvesTheCaller covers the second
// credential shape: the child's own device carries an enrolment ticket in the
// request BODY instead of a session header. The ticket and a session are
// mutually exclusive — presenting both would leave ambiguous which account the
// credential lands on — and a bare ticket must not authenticate anything else.
func TestHandler_PasskeyEnrolmentTicket_ResolvesTheCaller(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)

	msg := managedChildRequest("kid.one")
	msg.Password = ""
	msg.PasskeyEnrolment = true
	created, err := h.client.CreateManagedChildAccount(ctx, authedReq(connect.NewRequest(msg), adult))
	if err != nil {
		t.Fatalf("CreateManagedChildAccount: %v", err)
	}
	ticket := created.Msg.GetEnrolmentToken()
	if ticket == "" {
		t.Fatal("the passkey arm must mint an enrolment ticket")
	}

	t.Run("ticket alone reaches the child account", func(t *testing.T) {
		// The ceremony gets as far as the service, which means the handler
		// resolved the ticket's subject as the caller: a credential-less
		// refusal would have come back Unauthenticated instead.
		_, err := h.client.BeginPasskeyRegistration(ctx, connect.NewRequest(
			&identitypb.BeginPasskeyRegistrationRequest{EnrolmentToken: ticket},
		))
		if got := connectCodeOf(err); got == connect.CodeUnauthenticated {
			t.Fatalf("a valid ticket must resolve the caller, got %v", got)
		}
	})

	t.Run("session and ticket together are ambiguous", func(t *testing.T) {
		_, err := h.client.BeginPasskeyRegistration(ctx, authedReq(connect.NewRequest(
			&identitypb.BeginPasskeyRegistrationRequest{EnrolmentToken: ticket},
		), adult))
		if got := connectCodeOf(err); got != connect.CodeInvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", got)
		}
		_, err = h.client.CompletePasskeyRegistration(ctx, authedReq(connect.NewRequest(
			&identitypb.CompletePasskeyRegistrationRequest{EnrolmentToken: ticket},
		), adult))
		if got := connectCodeOf(err); got != connect.CodeInvalidArgument {
			t.Fatalf("complete: code = %v, want InvalidArgument", got)
		}
	})

	t.Run("neither session nor ticket is refused", func(t *testing.T) {
		_, err := h.client.BeginPasskeyRegistration(ctx, connect.NewRequest(
			&identitypb.BeginPasskeyRegistrationRequest{},
		))
		if got := connectCodeOf(err); got != connect.CodeUnauthenticated {
			t.Fatalf("code = %v, want Unauthenticated", got)
		}
		_, err = h.client.CompletePasskeyRegistration(ctx, connect.NewRequest(
			&identitypb.CompletePasskeyRegistrationRequest{},
		))
		if got := connectCodeOf(err); got != connect.CodeUnauthenticated {
			t.Fatalf("complete: code = %v, want Unauthenticated", got)
		}
	})

	t.Run("a garbage ticket is refused", func(t *testing.T) {
		_, err := h.client.BeginPasskeyRegistration(ctx, connect.NewRequest(
			&identitypb.BeginPasskeyRegistrationRequest{EnrolmentToken: "not-a-ticket"},
		))
		if got := connectCodeOf(err); got != connect.CodeUnauthenticated {
			t.Fatalf("code = %v, want Unauthenticated", got)
		}
	})
}
