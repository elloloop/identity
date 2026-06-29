package connect

import (
	"testing"

	"connectrpc.com/connect"

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
