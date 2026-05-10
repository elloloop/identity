package connect

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/service"
)

// errIDVNotWired is returned when a deployment did not configure an
// identity-verification provider. Clients should treat this as
// "feature disabled" rather than a transient failure.
var errIDVNotWired = errors.New("identity verification is not enabled in this deployment")

// ─── Identity Verification RPCs ─────────────────────────────────────────────

// BeginIdentityVerification starts a verification session for the caller.
func (h *IdentityHandler) BeginIdentityVerification(
	ctx context.Context,
	req *connect.Request[identitypb.BeginIdentityVerificationRequest],
) (*connect.Response[identitypb.BeginIdentityVerificationResponse], error) {
	if h.idv == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errIDVNotWired)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	res, err := h.idv.BeginIdentityVerification(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.BeginIdentityVerificationResponse{
		VerificationId: res.VerificationID,
		Provider:       res.Provider,
		SessionToken:   res.SessionToken,
		ExpiresAt:      timestamppb.New(res.ExpiresAt),
	}), nil
}

// GetIdentityVerificationStatus returns the current status of a verification.
func (h *IdentityHandler) GetIdentityVerificationStatus(
	ctx context.Context,
	req *connect.Request[identitypb.GetIdentityVerificationStatusRequest],
) (*connect.Response[identitypb.GetIdentityVerificationStatusResponse], error) {
	if h.idv == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errIDVNotWired)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	rec, err := h.idv.GetIdentityVerificationStatus(ctx, userID, req.Msg.GetVerificationId())
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.GetIdentityVerificationStatusResponse{
		Verification: idvRecordToProto(rec),
	}), nil
}

func idvRecordToProto(rec *service.IdentityVerificationRecord) *identitypb.IdentityVerification {
	if rec == nil {
		return nil
	}
	return &identitypb.IdentityVerification{
		Id:                rec.NodeID,
		UserId:            rec.UserID,
		TenantId:          rec.TenantID,
		Provider:          rec.Provider,
		ProviderSessionId: rec.ProviderSessionID,
		Status:            idvStatusToProto(rec.Status),
		CreatedAt:         msToTimestamp(rec.CreatedAt),
		UpdatedAt:         msToTimestamp(rec.UpdatedAt),
		CompletedAt:       msToTimestamp(rec.CompletedAt),
		RejectionReason:   rec.RejectionReason,
	}
}

func idvStatusToProto(s string) identitypb.IdentityVerificationStatus {
	switch s {
	case service.IDVStatusPending:
		return identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_PENDING
	case service.IDVStatusInReview:
		return identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_IN_REVIEW
	case service.IDVStatusApproved:
		return identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_APPROVED
	case service.IDVStatusRejected:
		return identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_REJECTED
	case service.IDVStatusExpired:
		return identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_EXPIRED
	default:
		return identitypb.IdentityVerificationStatus_IDENTITY_VERIFICATION_STATUS_UNSPECIFIED
	}
}
