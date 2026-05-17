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

	case errors.Is(err, service.ErrPermissionDenied):
		return connect.NewError(connect.CodePermissionDenied, err)

	case errors.Is(err, service.ErrAlreadyExists):
		return connect.NewError(connect.CodeAlreadyExists, err)

	case errors.Is(err, service.ErrUnauthenticated),
		errors.Is(err, service.ErrTokenExpired):
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

	case errors.Is(err, service.ErrTotpRequired):
		// Not really an error — the client must call VerifyTotp next.
		// Use FailedPrecondition to signal "you need to do something else first".
		return connect.NewError(connect.CodeFailedPrecondition, err)

	case errors.Is(err, service.ErrQrLoginExpired):
		return connect.NewError(connect.CodeDeadlineExceeded, err)

	case errors.Is(err, service.ErrInvalidTotpCode):
		return connect.NewError(connect.CodeUnauthenticated, err)

	case errors.Is(err, service.ErrNoPasswordSet),
		errors.Is(err, service.ErrAccountNotActive),
		errors.Is(err, service.ErrInvitationPending),
		errors.Is(err, service.ErrSignupDisabled),
		errors.Is(err, service.ErrIDVRequired):
		return connect.NewError(connect.CodeFailedPrecondition, err)

	case errors.Is(err, service.ErrInvitationUsed),
		errors.Is(err, service.ErrInvitationExpired):
		return connect.NewError(connect.CodeFailedPrecondition, err)

	case errors.Is(err, service.ErrQrLoginNotPending):
		return connect.NewError(connect.CodeFailedPrecondition, err)

	case errors.Is(err, service.ErrLocalAuthDisabled),
		errors.Is(err, service.ErrOAuthDisabled):
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
