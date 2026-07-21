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
