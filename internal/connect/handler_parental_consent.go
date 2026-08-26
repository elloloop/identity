package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// ─── Verifiable Parental Consent RPCs ───────────────────────────────────────

// GrantParentalConsent records verifiable parental consent for a child-band
// account and moves it out of USER_STATUS_PENDING_PARENTAL_CONSENT.
//
// The consenting adult's identity is taken from the authenticated session
// (X-Authenticated-User-Id, set by the auth middleware after verifying the
// JWT), NEVER from the request body — a modified client cannot assert who is
// consenting. The service enforces both mandatory checks (a strong verified
// factor on the adult's account AND a step-up re-authentication).
func (h *IdentityHandler) GrantParentalConsent(
	ctx context.Context,
	req *connect.Request[identitypb.GrantParentalConsentRequest],
) (*connect.Response[identitypb.GrantParentalConsentResponse], error) {
	consentingUserID := authenticatedUserID(req.Header())
	if consentingUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	rec, err := h.auth.GrantParentalConsent(
		ctx,
		consentingUserID,
		req.Msg.GetChildUserId(),
		req.Msg.GetPolicyVersion(),
		req.Msg.GetStepUpPassword(),
		clientIP(req.Header()),
		clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.GrantParentalConsentResponse{
		Record:      consentRecordToProto(rec),
		ChildStatus: userStatusToProto(service.StatusActive),
	}), nil
}

// RevokeParentalConsent withdraws a previously-granted consent, re-gating the
// child account. Only the adult who granted the consent (the authenticated
// caller) may revoke it; the service enforces that.
func (h *IdentityHandler) RevokeParentalConsent(
	ctx context.Context,
	req *connect.Request[identitypb.RevokeParentalConsentRequest],
) (*connect.Response[identitypb.RevokeParentalConsentResponse], error) {
	actorUserID := authenticatedUserID(req.Header())
	if actorUserID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	rec, err := h.auth.RevokeParentalConsent(ctx, actorUserID, req.Msg.GetChildUserId(), req.Msg.GetReason())
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&identitypb.RevokeParentalConsentResponse{
		Record:      consentRecordToProto(rec),
		ChildStatus: userStatusToProto(service.StatusPendingParentalConsent),
	}), nil
}

func consentRecordToProto(rec *service.ParentalConsentRecord) *identitypb.ConsentRecord {
	if rec == nil {
		return nil
	}
	return &identitypb.ConsentRecord{
		Id:                  rec.ConsentID,
		ChildUserId:         rec.ChildUserID,
		ConsentingUserId:    rec.ConsentingUserID,
		PolicyVersion:       rec.PolicyVersion,
		GrantedAt:           msToTimestamp(rec.GrantedAt),
		VerificationFactors: consentFactorsToProto(rec.Factors),
		SteppedUp:           rec.SteppedUp,
		ConsentIp:           rec.ConsentIP,
		ConsentUserAgent:    rec.ConsentUserAgent,
		RevokedAt:           msToTimestamp(rec.RevokedAt),
		RevokedByUserId:     rec.RevokedByUserID,
		Market:              rec.Market,
	}
}

func consentFactorsToProto(csv string) []identitypb.ParentalConsentVerificationFactor {
	factors := service.DecodeConsentFactors(csv)
	if len(factors) == 0 {
		return nil
	}
	out := make([]identitypb.ParentalConsentVerificationFactor, 0, len(factors))
	for _, f := range factors {
		out = append(out, consentFactorToProto(f))
	}
	return out
}

func consentFactorToProto(f service.ParentalConsentFactor) identitypb.ParentalConsentVerificationFactor {
	switch f {
	case service.ParentalConsentFactorVerifiedPhone:
		return identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_VERIFIED_PHONE
	case service.ParentalConsentFactorPasskey:
		return identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_PASSKEY
	case service.ParentalConsentFactorIdentityVerification:
		return identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_IDENTITY_VERIFICATION
	default:
		return identitypb.ParentalConsentVerificationFactor_PARENTAL_CONSENT_VERIFICATION_FACTOR_UNSPECIFIED
	}
}
