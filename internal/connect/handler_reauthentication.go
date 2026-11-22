package connect

import (
	"context"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

func passkeyReauthentication(proof *identitypb.PasskeyReauthentication) *service.PasskeyReauthentication {
	if proof == nil {
		return nil
	}
	return &service.PasskeyReauthentication{ChallengeID: proof.ChallengeId, CredentialJSON: proof.CredentialJson}
}

func (h *IdentityHandler) BeginReauthentication(ctx context.Context, req *connect.Request[identitypb.BeginReauthenticationRequest]) (*connect.Response[identitypb.BeginReauthenticationResponse], error) {
	userID := authenticatedUserID(req.Header())
	options, challenge, err := h.auth.BeginReauthentication(ctx, userID, authenticatedSignIn(req.Header()), req.Msg.Action, req.Msg.ResourceId)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.BeginReauthenticationResponse{OptionsJson: options, ChallengeId: challenge}), nil
}

func (h *IdentityHandler) VerifyReauthentication(ctx context.Context, req *connect.Request[identitypb.VerifyReauthenticationRequest]) (*connect.Response[identitypb.VerifyReauthenticationResponse], error) {
	userID := authenticatedUserID(req.Header())
	proof := &service.PasskeyReauthentication{ChallengeID: req.Msg.ChallengeId, CredentialJSON: req.Msg.CredentialJson}
	if err := h.auth.VerifyReauthentication(ctx, userID, authenticatedSignIn(req.Header()), proof, req.Msg.Action, req.Msg.ResourceId); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.VerifyReauthenticationResponse{UserId: userID}), nil
}
