package connect

import (
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// TestToConnectErrorParentalConsent proves the COPPA parental-consent gate
// maps to FailedPrecondition: the account exists but the client must complete
// the parental-consent flow before it can proceed (not an auth failure).
func TestToConnectErrorParentalConsent(t *testing.T) {
	err := toConnectError(service.ErrParentalConsentRequired)
	if err == nil {
		t.Fatal("toConnectError(ErrParentalConsentRequired) = nil, want error")
	}
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", got)
	}
}

// TestToConnectErrorEmailVerificationRequired proves the email-verification
// gate maps to FailedPrecondition: the account exists but the client must
// verify the email before it can authenticate (not an auth-credential failure).
func TestToConnectErrorEmailVerificationRequired(t *testing.T) {
	err := toConnectError(service.ErrEmailVerificationRequired)
	if err == nil {
		t.Fatal("toConnectError(ErrEmailVerificationRequired) = nil, want error")
	}
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", got)
	}
}

// TestToConnectErrorAccessNotAllowed proves a per-project access-allowlist
// denial maps to PermissionDenied: the authenticating email is not a member of
// the restricted project, an authorization failure (not FailedPrecondition or
// Unauthenticated, which would leak whether the account or its credential exist).
func TestToConnectErrorAccessNotAllowed(t *testing.T) {
	err := toConnectError(service.ErrAccessNotAllowed)
	if err == nil {
		t.Fatal("toConnectError(ErrAccessNotAllowed) = nil, want error")
	}
	if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", got)
	}
}

// TestToConnectErrorSessionExpired proves a session killed by the tenant's
// idle/absolute timeout maps to Unauthenticated (like ErrTokenExpired): the
// presented refresh token is no longer valid, so the client must re-authenticate
// — not a FailedPrecondition or an Internal error.
func TestToConnectErrorSessionExpired(t *testing.T) {
	err := toConnectError(service.ErrSessionExpired)
	if err == nil {
		t.Fatal("toConnectError(ErrSessionExpired) = nil, want error")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", got)
	}
}

// TestToConnectErrorProjectConfigConflict proves a config_json write that lost
// its optimistic-concurrency compare-and-swap after exhausting retries maps to
// Aborted — gRPC's retryable code for a concurrency/sequencer conflict, so the
// operator can simply retry the whole write.
func TestToConnectErrorProjectConfigConflict(t *testing.T) {
	err := toConnectError(service.ErrProjectConfigConflict)
	if err == nil {
		t.Fatal("toConnectError(ErrProjectConfigConflict) = nil, want error")
	}
	if got := connect.CodeOf(err); got != connect.CodeAborted {
		t.Fatalf("code = %v, want Aborted", got)
	}
}

// TestToConnectErrorMinorDataMinimized proves COPPA data-minimization rejection
// maps to FailedPrecondition: the account may not collect this PII, a "do
// something else" precondition rather than an auth or argument failure.
func TestToConnectErrorMinorDataMinimized(t *testing.T) {
	err := toConnectError(service.ErrMinorDataMinimized)
	if err == nil {
		t.Fatal("toConnectError(ErrMinorDataMinimized) = nil, want error")
	}
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", got)
	}
}

// TestToConnectErrorProductAgeRestricted pins the wire contract clients build
// against: an account refused by a product's age guardrail comes back as
// permission_denied with the stable `product_age_restricted` token in the
// message. Clients match on that token to show kind, child-appropriate copy, so
// neither the code nor the token may be reworded.
func TestToConnectErrorProductAgeRestricted(t *testing.T) {
	err := toConnectError(service.ErrProductAgeRestricted)
	if err == nil {
		t.Fatal("toConnectError(ErrProductAgeRestricted) = nil, want error")
	}
	if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", got)
	}
	if !strings.Contains(err.Error(), "product_age_restricted") {
		t.Fatalf("message = %q, want it to contain product_age_restricted", err.Error())
	}
}

// TestToConnectErrorDOBRequired pins the wire contract of the required-DOB
// completion step: the refusal is failed_precondition, the message leads with
// the stable `dob_required` token, and the completion ticket rides in an error
// detail the client can round-trip back into a typed DOBRequiredDetails. All
// three are the contract — clients match the token to show the DOB prompt and
// submit the ticket to SubmitDateOfBirth without a session.
func TestToConnectErrorDOBRequired(t *testing.T) {
	err := toConnectError(&service.DOBRequiredError{Ticket: "ticket-abc"})
	if err == nil {
		t.Fatal("toConnectError(DOBRequiredError) = nil, want error")
	}
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", got)
	}
	if !strings.Contains(err.Error(), "dob_required") {
		t.Fatalf("message = %q, want it to contain dob_required", err.Error())
	}

	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		t.Fatal("error is not a *connect.Error")
	}
	if len(cerr.Details()) != 1 {
		t.Fatalf("details = %d, want exactly 1 (the completion ticket)", len(cerr.Details()))
	}
	msg, derr := cerr.Details()[0].Value()
	if derr != nil {
		t.Fatalf("detail Value: %v", derr)
	}
	details, ok := msg.(*identitypb.DOBRequiredDetails)
	if !ok {
		t.Fatalf("detail type = %T, want *DOBRequiredDetails", msg)
	}
	if details.CompletionToken != "ticket-abc" {
		t.Fatalf("completion_token = %q, want ticket-abc", details.CompletionToken)
	}

	// The sentinel alone (no typed ticket) still maps correctly, just with
	// no detail attached.
	plain := toConnectError(service.ErrDOBRequired)
	if got := connect.CodeOf(plain); got != connect.CodeFailedPrecondition {
		t.Fatalf("sentinel-only code = %v, want FailedPrecondition", got)
	}
}

// TestToConnectErrorDOBAlreadySet proves a repeat SubmitDateOfBirth maps to
// FailedPrecondition: the account state, not the request arguments, is what
// refuses the call.
func TestToConnectErrorDOBAlreadySet(t *testing.T) {
	err := toConnectError(service.ErrDOBAlreadySet)
	if err == nil {
		t.Fatal("toConnectError(ErrDOBAlreadySet) = nil, want error")
	}
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", got)
	}
}
