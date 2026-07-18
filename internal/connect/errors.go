package connect

import (
	"errors"

	"connectrpc.com/connect"

	"github.com/elloloop/identity/internal/service"
)

// toConnectError maps a service-layer error to the appropriate Connect error
// code. Unknown errors default to CodeInternal.
//
// The service layer defines sentinel errors in service/auth.go. This function
// checks against those using errors.Is so wrapped errors are handled correctly.
func toConnectError(err error) *connect.Error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, service.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)

	case errors.Is(err, service.ErrPermissionDenied),
		errors.Is(err, service.ErrAccessNotAllowed),
		errors.Is(err, service.ErrSignupByInvitationOnly),
		errors.Is(err, service.ErrCaptchaRequired),
		errors.Is(err, service.ErrCaptchaFailed):
		return connect.NewError(connect.CodePermissionDenied, err)

	case errors.Is(err, service.ErrAlreadyExists),
		errors.Is(err, service.ErrPhoneAlreadyVerified):
		return connect.NewError(connect.CodeAlreadyExists, err)

	case errors.Is(err, service.ErrUnauthenticated),
		errors.Is(err, service.ErrTokenExpired),
		errors.Is(err, service.ErrSessionExpired),
		errors.Is(err, service.ErrOAuthCodeInvalid),
		errors.Is(err, service.ErrEmailLoginCodeInvalid),
		errors.Is(err, service.ErrMagicLinkInvalid),
		errors.Is(err, service.ErrPhoneCodeInvalid),
		errors.Is(err, service.ErrNativeTokenReplayed):
		return connect.NewError(connect.CodeUnauthenticated, err)

	case errors.Is(err, service.ErrInvalidArgument),
		errors.Is(err, service.ErrWeakPassword):
		return connect.NewError(connect.CodeInvalidArgument, err)

	case errors.Is(err, service.ErrAccountLocked):
		// CodeResourceExhausted: lockout is a per-account quota of failed
		// attempts. ResourceExhausted matches gRPC's documented semantics
		// for "the resource is exhausted" / rate-limit-style failures and
		// signals to clients that the request itself is over-budget on
		// this resource (the account), not a transient infra failure
		// (which would be CodeUnavailable).
		return connect.NewError(connect.CodeResourceExhausted, err)

	case errors.Is(err, service.ErrTotpRequired),
		errors.Is(err, service.ErrSSORequired):
		// Not really an error — the client must do something else next
		// (call VerifyTotp, or start the tenant's SSO flow). Use
		// FailedPrecondition to signal "you need to do something else first".
		return connect.NewError(connect.CodeFailedPrecondition, err)

	case errors.Is(err, service.ErrQrLoginExpired):
		return connect.NewError(connect.CodeDeadlineExceeded, err)

	case errors.Is(err, service.ErrInvalidTotpCode):
		return connect.NewError(connect.CodeUnauthenticated, err)

	case errors.Is(err, service.ErrNoPasswordSet),
		errors.Is(err, service.ErrAccountNotActive),
		errors.Is(err, service.ErrInvitationPending),
		errors.Is(err, service.ErrSignupDisabled),
		errors.Is(err, service.ErrPasskeySignupDisabled),
		errors.Is(err, service.ErrNativeOAuthDisabled),
		errors.Is(err, service.ErrParentalConsentRequired),
		errors.Is(err, service.ErrIDVRequired),
		errors.Is(err, service.ErrEmailVerificationRequired),
		errors.Is(err, service.ErrAccountDeletionNotAllowed),
		errors.Is(err, service.ErrMinorDataMinimized):
		return connect.NewError(connect.CodeFailedPrecondition, err)

	case errors.Is(err, service.ErrInvitationUsed),
		errors.Is(err, service.ErrInvitationExpired):
		return connect.NewError(connect.CodeFailedPrecondition, err)

	case errors.Is(err, service.ErrLastOwner),
		errors.Is(err, service.ErrPlatformAdminExists),
		errors.Is(err, service.ErrFirstAdminBootstrapDisabled),
		errors.Is(err, service.ErrAuthDomainNotVerified),
		errors.Is(err, service.ErrProjectSecretsKeyMissing),
		errors.Is(err, service.ErrLastCredential):
		return connect.NewError(connect.CodeFailedPrecondition, err)

	case errors.Is(err, service.ErrQrLoginNotPending):
		return connect.NewError(connect.CodeFailedPrecondition, err)

	case errors.Is(err, service.ErrProjectConfigConflict):
		// A per-project config_json write lost its optimistic-concurrency
		// compare-and-swap after exhausting retries. CodeAborted is gRPC's
		// documented, retryable signal for a concurrency/sequencer conflict —
		// the operator can simply retry the whole write.
		return connect.NewError(connect.CodeAborted, err)

	case errors.Is(err, service.ErrLocalAuthDisabled),
		errors.Is(err, service.ErrOAuthDisabled),
		errors.Is(err, service.ErrSMSDisabled):
		return connect.NewError(connect.CodeUnavailable, err)

	case errors.Is(err, service.ErrUnimplemented):
		return connect.NewError(connect.CodeUnimplemented, err)
	}

	// Check for common error message patterns from the admin/group/help
	// services which return plain errors.New() instead of sentinel errors.
	msg := err.Error()
	switch {
	case containsAny(msg, "not found", "user not found", "group not found", "help request not found"):
		return connect.NewError(connect.CodeNotFound, err)
	case containsAny(msg, "admin role required", "admins cannot deactivate"):
		return connect.NewError(connect.CodePermissionDenied, err)
	case containsAny(msg, "already exists"):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case containsAny(msg, "is required", "must be", "valid email"):
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	return connect.NewError(connect.CodeInternal, err)
}

// containsAny returns true if s contains any of the given substrings.
func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
