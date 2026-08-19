package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// ── Verifiable Parental Consent ─────────────────────────────────────────
//
// A child-band account is created in StatusPendingParentalConsent (see
// auth_login.go) and cannot be issued access tokens until an adult grants
// verifiable, recorded, revocable parental consent for it. This file
// implements that grant/withdraw pair.
//
// The identity service is deliberately product-neutral: it models no
// "household" or "family". The caller's *relationship* to the child is
// established by whatever upstream system routes the request. What this
// surface guarantees is that the consenting adult is who they claim to be, to
// a standard proportionate to consenting on another person's behalf — closing
// the "an authenticated session is enough to consent" spoofing risk. Two
// independent, server-enforced checks are BOTH required to grant:
//
//  1. a STRONG VERIFIED FACTOR on the consenting adult's own account
//     (verified phone, a registered passkey, or an approved identity
//     verification), AND
//  2. a STEP-UP RE-AUTHENTICATION at the moment of consent (the adult
//     re-enters their password).
//
// A modified client cannot bypass either: the consenting adult's identity is
// taken from the verified session (never a request field), the step-up
// password is checked against the stored hash, and the factor check reads
// server-side account state.

// ParentalConsentFactor is a strong, server-verified factor present on the
// consenting adult's account at the instant consent was granted. It is the
// persisted (string) form of the proto
// ParentalConsentVerificationFactor enum.
type ParentalConsentFactor string

const (
	// ParentalConsentFactorVerifiedPhone is a phone number whose ownership the
	// adult verified via SMS OTP.
	ParentalConsentFactorVerifiedPhone ParentalConsentFactor = "verified_phone"
	// ParentalConsentFactorPasskey is a WebAuthn passkey registered to the
	// adult's account.
	ParentalConsentFactorPasskey ParentalConsentFactor = "passkey"
	// ParentalConsentFactorIdentityVerification is a document + selfie identity
	// verification that reached APPROVED.
	ParentalConsentFactorIdentityVerification ParentalConsentFactor = "identity_verification"
)

// ParentalConsentRecord is the auditable, revocable artifact proving a
// specific adult granted parental consent for a specific child account. It is
// retained as a compliance/audit record and survives deletion of either
// referenced user (matching the audit-trail retention posture), so it can
// defend a regulatory inquiry raised after an account is closed.
type ParentalConsentRecord struct {
	// ConsentID is the stable public identifier (the storage primary key).
	ConsentID string
	// ProjectID is the storage shard (ADR-0002): the per-request project.
	ProjectID   string
	ChildUserID string
	// ConsentingUserID is the adult who granted consent. The service derives it
	// from the authenticated caller, never from a client-supplied field.
	ConsentingUserID string
	// PolicyVersion identifies the direct-notice/privacy policy the adult was
	// shown before consenting.
	PolicyVersion string
	// Factors is the canonical, comma-separated, sorted list of the
	// ParentalConsentFactor values present at the moment of consent (>= 1).
	Factors string
	// SteppedUp is true for every persisted grant: the adult re-authenticated.
	SteppedUp        bool
	ConsentIP        string
	ConsentUserAgent string
	GrantedAt        int64 // epoch ms
	// RevokedAt is 0 while the consent is active; the epoch-ms instant it was
	// withdrawn otherwise. RevokedByUserID records who withdrew it.
	RevokedAt       int64
	RevokedByUserID string
}

// Parental-consent sentinel errors. The connect layer maps them to gRPC
// codes (see internal/connect/errors.go).
var (
	// ErrParentalConsentStepUpFailed is returned when the step-up
	// re-authentication at the moment of consent fails — a missing or wrong
	// step-up password, or a consenting account with no password set (so no
	// step-up is possible). Mapped to CodeUnauthenticated.
	ErrParentalConsentStepUpFailed = errors.New("parental consent step-up re-authentication failed")
	// ErrParentalConsentFactorMissing is returned when the consenting adult
	// holds no strong verified factor (verified phone / passkey / approved
	// identity verification), so their identity is not assured to the standard
	// required to consent on a child's behalf. Mapped to CodeFailedPrecondition.
	ErrParentalConsentFactorMissing = errors.New("consenting adult has no strong verified factor on file")
	// ErrParentalConsentNotPending is returned when the target child account is
	// not awaiting parental consent (it is not in pending_parental_consent), so
	// there is nothing to consent to. Mapped to CodeFailedPrecondition.
	ErrParentalConsentNotPending = errors.New("child account is not awaiting parental consent")
)

// encodeConsentFactors renders the factor set as a canonical, sorted,
// comma-separated string for storage and stable comparison.
func encodeConsentFactors(factors []ParentalConsentFactor) string {
	tokens := make([]string, 0, len(factors))
	for _, f := range factors {
		tokens = append(tokens, string(f))
	}
	sort.Strings(tokens)
	return strings.Join(tokens, ",")
}

// DecodeConsentFactors parses the canonical comma-separated factor string back
// into typed factors, dropping empty tokens. It is exported so the connect
// layer can map a stored record to the proto enum.
func DecodeConsentFactors(csv string) []ParentalConsentFactor {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]ParentalConsentFactor, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, ParentalConsentFactor(p))
	}
	return out
}

// isActiveConsentingAccount reports whether a consenting adult's account is in
// a state from which it may grant consent. A blank status (a legacy/newly
// created row) and "active" both qualify; any other status (deactivated,
// suspended, pending deletion, and — critically — pending_parental_consent, so
// one gated child cannot consent for another) does not.
func isActiveConsentingAccount(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", StatusActive:
		return true
	default:
		return false
	}
}

// strongVerifiedFactors returns the strong verified factors present on the
// adult's account right now. It is the single source of truth for check (a).
func (s *AuthService) strongVerifiedFactors(ctx context.Context, adult *User) ([]ParentalConsentFactor, error) {
	var factors []ParentalConsentFactor
	if adult.PhoneVerified {
		factors = append(factors, ParentalConsentFactorVerifiedPhone)
	}
	if adult.IDVVerified {
		factors = append(factors, ParentalConsentFactorIdentityVerification)
	}
	creds, err := s.repo(ctx).ListPasskeyCredentials(ctx, adult.ID)
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	if len(creds) > 0 {
		factors = append(factors, ParentalConsentFactorPasskey)
	}
	return factors, nil
}

// GrantParentalConsent records verifiable parental consent for a child-band
// account and transitions it out of pending_parental_consent to active.
//
// consentingUserID is the authenticated adult (derived by the handler from the
// verified session, NOT from the request body). childUserID is the child the
// consent is for. policyVersion identifies the notice the adult was shown.
// stepUpPassword re-authenticates the adult. ip/userAgent are recorded for the
// audit trail.
//
// BOTH checks are mandatory and enforced here, server-side:
//   - step-up re-auth: stepUpPassword must verify against the adult's stored
//     password hash;
//   - strong verified factor: the adult must hold >= 1 of verified phone /
//     passkey / approved identity verification.
//
// Failure of either is audit-logged with success=false (so a spoofing attempt
// is visible) and returns without mutating any account.
func (s *AuthService) GrantParentalConsent(
	ctx context.Context,
	consentingUserID, childUserID, policyVersion, stepUpPassword, ip, userAgent string,
) (*ParentalConsentRecord, error) {
	if consentingUserID == "" {
		return nil, ErrUnauthenticated
	}
	childUserID = strings.TrimSpace(childUserID)
	if childUserID == "" {
		return nil, fmt.Errorf("%w: child_user_id is required", ErrInvalidArgument)
	}
	policyVersion = strings.TrimSpace(policyVersion)
	if policyVersion == "" {
		return nil, fmt.Errorf("%w: policy_version is required", ErrInvalidArgument)
	}
	if childUserID == consentingUserID {
		return nil, fmt.Errorf("%w: an adult cannot grant parental consent for their own account", ErrInvalidArgument)
	}

	repo := s.repo(ctx)

	adult, err := repo.GetUser(ctx, consentingUserID)
	if err != nil {
		return nil, fmt.Errorf("fetch consenting user: %w", err)
	}
	if adult == nil {
		return nil, fmt.Errorf("%w: consenting user not found", ErrNotFound)
	}
	if !isActiveConsentingAccount(adult.Status) {
		return nil, ErrAccountNotActive
	}

	// Check (b): STEP-UP RE-AUTH. Verified before any state changes so a
	// caller holding only a session token (a hijacked session, a shared
	// device) cannot consent.
	if stepUpPassword == "" || adult.PasswordHash == "" || !passwords.Verify(stepUpPassword, adult.PasswordHash) {
		s.auditConsentFailure(ctx, consentingUserID, childUserID, "step_up", ip, userAgent)
		return nil, ErrParentalConsentStepUpFailed
	}

	// Check (a): STRONG VERIFIED FACTOR on the consenting adult's account.
	factors, err := s.strongVerifiedFactors(ctx, adult)
	if err != nil {
		return nil, fmt.Errorf("check verified factors: %w", err)
	}
	if len(factors) == 0 {
		s.auditConsentFailure(ctx, consentingUserID, childUserID, "verified_factor", ip, userAgent)
		return nil, ErrParentalConsentFactorMissing
	}

	child, err := repo.GetUser(ctx, childUserID)
	if err != nil {
		return nil, fmt.Errorf("fetch child user: %w", err)
	}
	if child == nil {
		return nil, fmt.Errorf("%w: child user not found", ErrNotFound)
	}
	// A grant is only meaningful for a gated child. This also prevents a
	// second grant on an already-consented (active) child — the double-grant
	// guard.
	if strings.ToLower(child.Status) != StatusPendingParentalConsent {
		return nil, ErrParentalConsentNotPending
	}

	// Records are written before the status flip so the invariant "an active
	// child always has a consent record" can never be violated by a mid-
	// operation failure (a failed flip leaves the child gated, never wrongly
	// active). If a prior grant recorded consent but failed to flip the
	// status, a retry finds the existing active record here and simply
	// completes the activation, idempotently.
	if existing, gErr := repo.GetActiveParentalConsentForChild(ctx, childUserID); gErr != nil {
		return nil, fmt.Errorf("check existing consent: %w", gErr)
	} else if existing != nil {
		return s.finishConsentActivation(ctx, existing, ip, userAgent)
	}

	now := s.nowMs()
	rec := &ParentalConsentRecord{
		ConsentID:        "pconsent_" + randomToken(16),
		ProjectID:        s.projectID(ctx),
		ChildUserID:      childUserID,
		ConsentingUserID: consentingUserID,
		PolicyVersion:    policyVersion,
		Factors:          encodeConsentFactors(factors),
		SteppedUp:        true,
		ConsentIP:        ip,
		ConsentUserAgent: userAgent,
		GrantedAt:        now,
	}
	if err := repo.CreateParentalConsent(ctx, rec); err != nil {
		return nil, fmt.Errorf("record parental consent: %w", err)
	}

	if err := repo.UpdateUser(ctx, childUserID, map[string]any{
		"status":     StatusActive,
		"updated_at": now,
	}); err != nil {
		return nil, fmt.Errorf("activate child account: %w", err)
	}

	s.audit.Log(
		ctx, audit.EventParentalConsentGranted,
		audit.WithActor(consentingUserID), audit.WithTarget(childUserID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"consent_id":     rec.ConsentID,
			"policy_version": policyVersion,
			"factors":        rec.Factors,
		}),
	)
	return rec, nil
}

// finishConsentActivation completes a half-applied prior grant: the consent
// record already exists (both checks having passed on the earlier attempt) but
// the child is still gated. It re-asserts the status flip idempotently and
// returns the existing record.
func (s *AuthService) finishConsentActivation(
	ctx context.Context, rec *ParentalConsentRecord, ip, userAgent string,
) (*ParentalConsentRecord, error) {
	now := s.nowMs()
	if err := s.repo(ctx).UpdateUser(ctx, rec.ChildUserID, map[string]any{
		"status":     StatusActive,
		"updated_at": now,
	}); err != nil {
		return nil, fmt.Errorf("activate child account: %w", err)
	}
	s.audit.Log(
		ctx, audit.EventParentalConsentGranted,
		audit.WithActor(rec.ConsentingUserID), audit.WithTarget(rec.ChildUserID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"consent_id": rec.ConsentID, "resumed": true}),
	)
	return rec, nil
}

// auditConsentFailure records a rejected consent attempt so a spoofing attempt
// (a session-only actor, or an adult with no verified factor) is visible in the
// audit trail. step names which check failed.
func (s *AuthService) auditConsentFailure(ctx context.Context, actorID, childID, step, ip, userAgent string) {
	s.audit.Log(
		ctx, audit.EventParentalConsentGranted,
		audit.WithActor(actorID), audit.WithTarget(childID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent), audit.WithSuccess(false),
		audit.WithDetails(map[string]any{"step": step}),
	)
}

// RevokeParentalConsent withdraws a previously-granted parental consent,
// re-gating the child account (active -> pending_parental_consent) and cutting
// off its access immediately. Consent must be revocable (all three regimes
// require a right to withdraw).
//
// actorUserID is the authenticated caller (from the verified session). Only the
// adult who granted the consent may revoke it: the identity service models no
// household, so the recorded consenter is the authority. reason is optional
// free text retained for the audit trail.
func (s *AuthService) RevokeParentalConsent(
	ctx context.Context, actorUserID, childUserID, reason string,
) (*ParentalConsentRecord, error) {
	if actorUserID == "" {
		return nil, ErrUnauthenticated
	}
	childUserID = strings.TrimSpace(childUserID)
	if childUserID == "" {
		return nil, fmt.Errorf("%w: child_user_id is required", ErrInvalidArgument)
	}

	repo := s.repo(ctx)
	active, err := repo.GetActiveParentalConsentForChild(ctx, childUserID)
	if err != nil {
		return nil, fmt.Errorf("fetch active consent: %w", err)
	}
	if active == nil {
		return nil, fmt.Errorf("%w: no active parental consent for this child", ErrNotFound)
	}
	if active.ConsentingUserID != actorUserID {
		return nil, fmt.Errorf("%w: only the consenting adult may revoke this consent", ErrPermissionDenied)
	}

	now := s.nowMs()

	// Re-gate the child BEFORE marking the record revoked so the invariant
	// "an active child always has an active consent record" holds through any
	// mid-operation failure. A failed record-revoke after re-gating leaves the
	// child gated (safe) and the record still active; a retry re-gates
	// idempotently and re-attempts the revoke.
	child, err := repo.GetUser(ctx, childUserID)
	if err != nil {
		return nil, fmt.Errorf("fetch child user: %w", err)
	}
	if child != nil && strings.ToLower(child.Status) == StatusActive {
		if err := repo.UpdateUser(ctx, childUserID, map[string]any{
			"status":     StatusPendingParentalConsent,
			"updated_at": now,
		}); err != nil {
			return nil, fmt.Errorf("re-gate child account: %w", err)
		}
		if err := revokeAllUserSessions(ctx, repo, childUserID, now); err != nil {
			return nil, fmt.Errorf("revoke child sessions: %w", err)
		}
	}

	if err := repo.MarkParentalConsentRevoked(ctx, active.ConsentID, actorUserID, now); err != nil {
		return nil, fmt.Errorf("revoke parental consent: %w", err)
	}
	active.RevokedAt = now
	active.RevokedByUserID = actorUserID

	s.audit.Log(
		ctx, audit.EventParentalConsentRevoked,
		audit.WithActor(actorUserID), audit.WithTarget(childUserID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"consent_id": active.ConsentID, "reason": reason}),
	)
	return active, nil
}
