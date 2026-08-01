package connect

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	identityv1 "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// CreateAssuranceChallenge issues a one-time attestation nonce.
func (h *IdentityHandler) CreateAssuranceChallenge(
	ctx context.Context,
	req *connect.Request[identityv1.CreateAssuranceChallengeRequest],
) (*connect.Response[identityv1.CreateAssuranceChallengeResponse], error) {
	if h.cfg == nil || !h.cfg.AssuranceEnabled {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrAssuranceDisabled)
	}
	ch, err := h.auth.CreateAssuranceChallenge(ctx, req.Msg.Platform)
	if err != nil {
		return nil, mapAssuranceError(err)
	}
	return connect.NewResponse(&identityv1.CreateAssuranceChallengeResponse{
		ChallengeId: ch.ID,
		Challenge:   ch.Challenge,
		ExpiresAtMs: ch.ExpiresAt,
	}), nil
}

// IssueAssuranceToken exchanges platform evidence for an assurance token.
func (h *IdentityHandler) IssueAssuranceToken(
	ctx context.Context,
	req *connect.Request[identityv1.IssueAssuranceTokenRequest],
) (*connect.Response[identityv1.IssueAssuranceTokenResponse], error) {
	tok, err := h.auth.IssueAssuranceToken(ctx, service.AssuranceEvidence{
		Platform:          req.Msg.Platform,
		ChallengeID:       req.Msg.ChallengeId,
		KeyID:             req.Msg.KeyId,
		AttestationObject: req.Msg.AttestationObject,
		IntegrityToken:    req.Msg.IntegrityToken,
		WebToken:          req.Msg.WebToken,
		ClientIP:          clientIP(req.Header()),
	})
	if err != nil {
		return nil, mapAssuranceError(err)
	}
	return connect.NewResponse(&identityv1.IssueAssuranceTokenResponse{
		AssuranceToken: tok.Token,
		ExpiresAtMs:    tok.ExpiresAt,
	}), nil
}

// RefreshAssuranceToken renews an assurance token via an App Attest
// assertion.
func (h *IdentityHandler) RefreshAssuranceToken(
	ctx context.Context,
	req *connect.Request[identityv1.RefreshAssuranceTokenRequest],
) (*connect.Response[identityv1.RefreshAssuranceTokenResponse], error) {
	tok, err := h.auth.RefreshAssuranceToken(ctx, req.Msg.ChallengeId, req.Msg.KeyId, req.Msg.Assertion)
	if err != nil {
		return nil, mapAssuranceError(err)
	}
	return connect.NewResponse(&identityv1.RefreshAssuranceTokenResponse{
		AssuranceToken: tok.Token,
		ExpiresAtMs:    tok.ExpiresAt,
	}), nil
}

// mapAssuranceError translates assurance service errors to connect
// codes: a disabled surface is Unimplemented (matching how other
// optional surfaces report), a rejection is PermissionDenied (via the
// shared mapper), everything else falls through to the generic mapping.
func mapAssuranceError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, service.ErrAssuranceDisabled) {
		return connect.NewError(connect.CodeUnimplemented, err)
	}
	return toConnectError(err)
}
