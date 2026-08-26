package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/passwords"
)

const (
	consentTestPassword = "MyStr0ng!Pass"
	consentTestPolicy   = "children-privacy-notice-v1"
)

func seedConsentAdult(ctx context.Context, t *testing.T, h *testHarness, email string, phoneVerified bool) string {
	t.Helper()
	hash, err := passwords.Hash(consentTestPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	id, err := h.repo.CreateUser(ctx, &service.User{
		Email: email, Status: "active", Role: "member",
		PasswordHash: hash, PhoneVerified: phoneVerified,
	})
	if err != nil {
		t.Fatalf("seed adult: %v", err)
	}
	return id
}

func seedConsentChild(ctx context.Context, t *testing.T, h *testHarness, email string) string {
	t.Helper()
	id, err := h.repo.CreateUser(ctx, &service.User{
		Email: email, Status: service.StatusPendingParentalConsent, Role: "member",
	})
	if err != nil {
		t.Fatalf("seed child: %v", err)
	}
	return id
}

// TestHandler_GrantParentalConsent_HappyPath exercises the full RPC path and
// confirms the consenting adult's identity is taken from the authenticated
// session and stamped onto the returned record.
func TestHandler_GrantParentalConsent_HappyPath(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
	child := seedConsentChild(ctx, t, h, "child@example.com")

	req := connect.NewRequest(&identitypb.GrantParentalConsentRequest{
		ChildUserId:    child,
		PolicyVersion:  consentTestPolicy,
		StepUpPassword: consentTestPassword,
	})
	authedReq(req, adult)

	res, err := h.client.GrantParentalConsent(ctx, req)
	if err != nil {
		t.Fatalf("GrantParentalConsent: %v", err)
	}
	if res.Msg.Record.GetConsentingUserId() != adult {
		t.Fatalf("consenting id = %q, want %q (server-derived)", res.Msg.Record.GetConsentingUserId(), adult)
	}
	if res.Msg.Record.GetChildUserId() != child {
		t.Fatalf("child id = %q, want %q", res.Msg.Record.GetChildUserId(), child)
	}
	if res.Msg.GetChildStatus() != identitypb.UserStatus_USER_STATUS_ACTIVE {
		t.Fatalf("child status = %v, want ACTIVE", res.Msg.GetChildStatus())
	}
	if !res.Msg.Record.GetSteppedUp() {
		t.Fatal("record must mark stepped_up")
	}
	factors := res.Msg.Record.GetVerificationFactors()
	if len(factors) != 1 || factors[0] != identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_VERIFIED_PHONE {
		t.Fatalf("factors = %v, want [VERIFIED_PHONE]", factors)
	}
}

// TestHandler_GrantParentalConsent_RequiresAuthenticatedSession proves a client
// with no verified session (no X-Authenticated-User-Id) cannot consent — the
// consenting identity is never taken from the request body.
func TestHandler_GrantParentalConsent_RequiresAuthenticatedSession(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	child := seedConsentChild(ctx, t, h, "child@example.com")

	// No authedReq: the request carries no authenticated caller.
	req := connect.NewRequest(&identitypb.GrantParentalConsentRequest{
		ChildUserId:    child,
		PolicyVersion:  consentTestPolicy,
		StepUpPassword: consentTestPassword,
	})
	_, err := h.client.GrantParentalConsent(ctx, req)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

// TestHandler_GrantParentalConsent_ModifiedClientCannotBypass proves the two
// server-side checks cannot be skipped from the client. An authenticated actor
// with no strong verified factor is rejected, and a wrong step-up password is
// rejected — neither can assert another (verified) adult's identity, because
// the caller is fixed by the session, not the payload.
func TestHandler_GrantParentalConsent_ModifiedClientCannotBypass(t *testing.T) {
	ctx := context.Background()
	t.Run("actor without a verified factor is refused", func(t *testing.T) {
		h := newHarness(t)
		impostor := seedConsentAdult(ctx, t, h, "impostor@example.com", false) // no verified factor
		child := seedConsentChild(ctx, t, h, "child@example.com")

		req := connect.NewRequest(&identitypb.GrantParentalConsentRequest{
			ChildUserId:    child,
			PolicyVersion:  consentTestPolicy,
			StepUpPassword: consentTestPassword,
		})
		authedReq(req, impostor)

		_, err := h.client.GrantParentalConsent(ctx, req)
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("code = %v, want FailedPrecondition", connect.CodeOf(err))
		}
		got, _ := h.repo.GetUser(ctx, child)
		if got.Status != service.StatusPendingParentalConsent {
			t.Fatalf("child must stay gated, status = %q", got.Status)
		}
	})

	t.Run("wrong step-up password is refused", func(t *testing.T) {
		h := newHarness(t)
		adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
		child := seedConsentChild(ctx, t, h, "child@example.com")

		req := connect.NewRequest(&identitypb.GrantParentalConsentRequest{
			ChildUserId:    child,
			PolicyVersion:  consentTestPolicy,
			StepUpPassword: "not-the-password",
		})
		authedReq(req, adult)

		_, err := h.client.GrantParentalConsent(ctx, req)
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("code = %v, want Unauthenticated", connect.CodeOf(err))
		}
	})
}

func TestHandler_RevokeParentalConsent(t *testing.T) {
	ctx := context.Background()
	grant := func(t *testing.T, h *testHarness, adult, child string) {
		t.Helper()
		req := connect.NewRequest(&identitypb.GrantParentalConsentRequest{
			ChildUserId: child, PolicyVersion: consentTestPolicy, StepUpPassword: consentTestPassword,
		})
		authedReq(req, adult)
		if _, err := h.client.GrantParentalConsent(ctx, req); err != nil {
			t.Fatalf("grant: %v", err)
		}
	}

	t.Run("consenter revokes and child is re-gated", func(t *testing.T) {
		h := newHarness(t)
		adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
		child := seedConsentChild(ctx, t, h, "child@example.com")
		grant(t, h, adult, child)

		req := connect.NewRequest(&identitypb.RevokeParentalConsentRequest{ChildUserId: child, Reason: "withdrawn"})
		authedReq(req, adult)
		res, err := h.client.RevokeParentalConsent(ctx, req)
		if err != nil {
			t.Fatalf("RevokeParentalConsent: %v", err)
		}
		if res.Msg.GetChildStatus() != identitypb.UserStatus_USER_STATUS_PENDING_PARENTAL_CONSENT {
			t.Fatalf("child status = %v, want PENDING_PARENTAL_CONSENT", res.Msg.GetChildStatus())
		}
		if res.Msg.Record.GetRevokedAt() == nil {
			t.Fatal("record must carry revoked_at")
		}
	})

	t.Run("a different authenticated user cannot revoke", func(t *testing.T) {
		h := newHarness(t)
		adult := seedConsentAdult(ctx, t, h, "adult@example.com", true)
		other := seedConsentAdult(ctx, t, h, "other@example.com", true)
		child := seedConsentChild(ctx, t, h, "child@example.com")
		grant(t, h, adult, child)

		req := connect.NewRequest(&identitypb.RevokeParentalConsentRequest{ChildUserId: child})
		authedReq(req, other)
		_, err := h.client.RevokeParentalConsent(ctx, req)
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("code = %v, want PermissionDenied", connect.CodeOf(err))
		}
	})
}

// TestHandler_RevokeParentalConsent_RequiresAuthenticatedSession proves revoke,
// like grant, refuses a caller with no verified session: the acting identity is
// the session, never the request body.
func TestHandler_RevokeParentalConsent_RequiresAuthenticatedSession(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	child := seedConsentChild(ctx, t, h, "child@example.com")

	// No authedReq: the request carries no authenticated caller.
	req := connect.NewRequest(&identitypb.RevokeParentalConsentRequest{ChildUserId: child})
	_, err := h.client.RevokeParentalConsent(ctx, req)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

// TestConsentRecordToProto_Nil confirms the mapper is nil-safe: a nil record
// (a defensive contract the callers rely on) maps to a nil proto rather than
// panicking.
func TestConsentRecordToProto_Nil(t *testing.T) {
	if got := consentRecordToProto(nil); got != nil {
		t.Fatalf("consentRecordToProto(nil) = %v, want nil", got)
	}
}

// TestConsentFactorsToProto covers the factor-set mapper's two ends: an empty
// stored factor string maps to no proto factors, and a populated one maps each
// token to its enum.
func TestConsentFactorsToProto(t *testing.T) {
	if got := consentFactorsToProto(""); got != nil {
		t.Fatalf("consentFactorsToProto(%q) = %v, want nil", "", got)
	}

	got := consentFactorsToProto("identity_verification,passkey,verified_phone")
	want := []identitypb.ParentalConsentVerificationFactor{
		identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_IDENTITY_VERIFICATION,
		identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_PASSKEY,
		identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_VERIFIED_PHONE,
	}
	if len(got) != len(want) {
		t.Fatalf("consentFactorsToProto = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("factor[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

// TestConsentFactorToProto maps every strong factor to its proto enum, and an
// unrecognised factor to UNSPECIFIED rather than an arbitrary value.
func TestConsentFactorToProto(t *testing.T) {
	cases := map[service.ParentalConsentFactor]identitypb.ParentalConsentVerificationFactor{
		service.ParentalConsentFactorVerifiedPhone:         identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_VERIFIED_PHONE,
		service.ParentalConsentFactorPasskey:               identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_PASSKEY,
		service.ParentalConsentFactorIdentityVerification:  identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_IDENTITY_VERIFICATION,
		service.ParentalConsentFactor("not-a-real-factor"): identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_UNSPECIFIED,
	}
	for factor, want := range cases {
		if got := consentFactorToProto(factor); got != want {
			t.Fatalf("consentFactorToProto(%q) = %v, want %v", factor, got, want)
		}
	}
}
