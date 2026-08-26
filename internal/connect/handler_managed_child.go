package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// ─── Managed child account RPCs ─────────────────────────────────────────────

// CreateManagedChildAccount is the parent-creates-child flow: the
// authenticated adult creates a minor's account, born USER_STATUS_ACTIVE
// under the caller's guardianship, with the guardian edge and the
// parental-consent record committed atomically in the same write.
//
// The calling adult's identity is taken from the authenticated session
// (X-Authenticated-User-Id, set by the auth middleware after verifying the
// JWT), NEVER from the request body — the request message deliberately
// carries no caller identity field, so a modified client cannot assert who is
// creating the account. The service enforces both mandatory checks (a strong
// verified factor on the adult's account AND a step-up re-authentication).
func (h *IdentityHandler) CreateManagedChildAccount(
	ctx context.Context,
	req *connect.Request[identitypb.CreateManagedChildAccountRequest],
) (*connect.Response[identitypb.CreateManagedChildAccountResponse], error) {
	callerUserID := authenticatedUserID(req.Header())
	if callerUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	result, err := h.auth.CreateManagedChildAccount(
		ctx,
		callerUserID,
		service.ManagedChildAccountRequest{
			Username:         req.Msg.GetUsername(),
			DisplayName:      req.Msg.GetDisplayName(),
			DateOfBirthMs:    req.Msg.GetDateOfBirthMs(),
			Market:           req.Msg.GetMarket(),
			AvatarURL:        req.Msg.GetAvatarUrl(),
			Password:         req.Msg.GetPassword(),
			PasskeyEnrolment: req.Msg.GetPasskeyEnrolment(),
			PolicyVersion:    req.Msg.GetPolicyVersion(),
			StepUpPassword:   req.Msg.GetStepUpPassword(),
		},
		clientIP(req.Header()),
		clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.CreateManagedChildAccountResponse{
		Child:          userToProto(result.Child),
		Consent:        consentRecordToProto(result.Consent),
		EnrolmentToken: result.EnrolmentTicket,
	}), nil
}
