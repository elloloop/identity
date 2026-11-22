package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

func (h *IdentityHandler) BeginPasskeyEligibilityVerification(ctx context.Context, req *connect.Request[identitypb.BeginPasskeyEligibilityVerificationRequest]) (*connect.Response[identitypb.BeginPasskeyEligibilityVerificationResponse], error) {
	options, id, err := h.auth.BeginPasskeyEligibilityVerification(ctx, authenticatedUserID(req.Header()), authenticatedSignIn(req.Header()), req.Msg.CredentialId)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.BeginPasskeyEligibilityVerificationResponse{OptionsJson: options, ChallengeId: id}), nil
}

func (h *IdentityHandler) CompletePasskeyEligibilityVerification(ctx context.Context, req *connect.Request[identitypb.CompletePasskeyEligibilityVerificationRequest]) (*connect.Response[identitypb.CompletePasskeyEligibilityVerificationResponse], error) {
	info, err := h.auth.CompletePasskeyEligibilityVerification(ctx, authenticatedUserID(req.Header()), authenticatedSignIn(req.Header()), req.Msg.CredentialId, &service.PasskeyReauthentication{ChallengeID: req.Msg.ChallengeId, CredentialJSON: req.Msg.CredentialJson})
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CompletePasskeyEligibilityVerificationResponse{Credential: passkeyToProto(info)}), nil
}
