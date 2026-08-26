package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/idv"
)

// IdentityVerificationService orchestrates document + selfie
// verification through a pluggable idv.Provider, persisting one
// IdentityVerificationRecord per session against the user.
//
// The caller-facing identifier (VerificationID) is server-issued; the
// provider's own session id is stored alongside but never returned to
// the client.
type IdentityVerificationService struct {
	defaultRepo      Repository
	provider         idv.Provider
	defaultProjectID string
	clock            func() time.Time
	newID            func() string
	logger           *zap.Logger
	// minorData refuses to begin identity verification for a CHILD-band
	// account (COPPA data-minimization). A zero-value minimizer is a safe
	// no-op, so a caller that omits WithMinorDataMinimizer behaves exactly
	// as before.
	minorData MinorDataMinimizer
}

// NewIdentityVerificationService constructs the service. clock and
// newID default to time.Now / a hex random id when nil.
func NewIdentityVerificationService(
	repo Repository,
	provider idv.Provider,
	projectID string,
	logger *zap.Logger,
) *IdentityVerificationService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &IdentityVerificationService{
		defaultRepo:      repo,
		provider:         provider,
		defaultProjectID: projectID,
		clock:            time.Now,
		newID:            newVerificationID,
		logger:           logger,
	}
}

// WithMinorDataMinimizer wires COPPA data-minimization: when the minimizer is
// active, a CHILD-band account cannot begin identity verification. Returns the
// service for chaining. Off by default (zero-value minimizer is a no-op).
func (s *IdentityVerificationService) WithMinorDataMinimizer(m MinorDataMinimizer) *IdentityVerificationService {
	s.minorData = m
	return s
}

// projectID returns the storage shard (project) the request operates under:
// the per-request ProjectScope when present, else the boot default.
func (s *IdentityVerificationService) projectID(ctx context.Context) string {
	return requestProjectID(ctx, s.defaultProjectID)
}

// repo returns the Repository bound to the request's project (ADR-0002),
// falling back to the boot-default project when no scope is present.
func (s *IdentityVerificationService) repo(ctx context.Context) Repository {
	return scopedRepository(ctx, s.defaultRepo, s.defaultProjectID)
}

// BeginIdentityVerification creates a new verification session for
// the given user. It allocates a server-side VerificationID, asks the
// provider to mint a client session token, and persists a PENDING
// record so subsequent status polls have something to read.
//
// Returns ErrNotFound when userID does not resolve to a user, and
// ErrAnonymousMustUpgrade when it resolves to an anonymous one.
func (s *IdentityVerificationService) BeginIdentityVerification(
	ctx context.Context,
	userID string,
) (*BeginIdentityVerificationResult, error) {
	if userID == "" {
		return nil, ErrUnauthenticated
	}
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("idv: lookup user: %w", err)
	}
	if user == nil {
		return nil, ErrNotFound
	}
	// The one-door invariant refuseAnonymousCredentialAttach enforces on the
	// credential surfaces extends here: an anonymous access token carries a
	// sub and role:member like any other, but the account it names can still
	// be hard-deleted by the retention sweep — which would orphan the
	// verification — and each BeginVerification is a PAID provider call an
	// unauthenticated caller could otherwise drive by chaining
	// SignInAnonymously. The minor-data check below is blind to the account
	// class too: no date of birth means BandUnknown, which passes.
	if user.IsAnonymous {
		return nil, fmt.Errorf(
			"%w: identity verification is refused while the account can still be "+
				"hard-deleted by the anonymous retention sweep", ErrAnonymousMustUpgrade,
		)
	}
	// COPPA data-minimization: never collect identity documents from a
	// CHILD-band account when minimization is enabled. No provider session
	// is created. Adults/teens and minimization-off deployments are
	// unaffected.
	if s.minorData.BlocksChildFor(ctx, user) {
		s.logger.Info("idv_begin_blocked_minor", zap.String("user_id", userID))
		return nil, ErrMinorDataMinimized
	}

	sess, err := s.provider.BeginVerification(ctx, idv.Request{
		UserID:      userID,
		TenantID:    s.projectID(ctx),
		Email:       user.Email,
		DisplayName: user.Name,
	})
	if err != nil {
		s.logger.Error(
			"idv_begin_provider_failed",
			zap.String("provider", s.provider.Name()),
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("idv: provider begin: %w", err)
	}

	now := s.clock().UnixMilli()
	rec := &IdentityVerificationRecord{
		VerificationID:    s.newID(),
		UserID:            userID,
		ProjectID:         s.projectID(ctx),
		Provider:          s.provider.Name(),
		ProviderSessionID: sess.ProviderSessionID,
		Status:            IDVStatusPending,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.repo(ctx).CreateIdentityVerification(ctx, rec); err != nil {
		return nil, fmt.Errorf("idv: persist: %w", err)
	}

	return &BeginIdentityVerificationResult{
		VerificationID: rec.VerificationID,
		Provider:       s.provider.Name(),
		SessionToken:   sess.SessionToken,
		ExpiresAt:      sess.ExpiresAt,
	}, nil
}

// GetIdentityVerificationStatus returns the current state of a
// verification. When verificationID is empty the caller's latest
// session is returned; this matches the "what's my status?" query
// the client SDK makes most often.
//
// For sessions whose persisted state is non-terminal, the provider
// is consulted and the local record is updated if a verdict has
// arrived.
//
// Returns ErrNotFound when no matching session exists, and
// ErrPermissionDenied when the caller is not the owner.
func (s *IdentityVerificationService) GetIdentityVerificationStatus(
	ctx context.Context,
	callerUserID, verificationID string,
) (*IdentityVerificationRecord, error) {
	if callerUserID == "" {
		return nil, ErrUnauthenticated
	}

	rec, err := s.lookupForCaller(ctx, callerUserID, verificationID)
	if err != nil {
		return nil, err
	}

	if isTerminalIDVStatus(rec.Status) {
		return rec, nil
	}

	status, err := s.provider.GetVerification(ctx, rec.ProviderSessionID)
	if errors.Is(err, idv.ErrSessionNotFound) {
		// Provider lost the session; mark it expired so future polls
		// short-circuit on the terminal status.
		now := s.clock().UnixMilli()
		_ = s.repo(ctx).UpdateIdentityVerificationStatus(ctx, rec.VerificationID, IDVStatusExpired, "", now, now)
		rec.Status = IDVStatusExpired
		rec.CompletedAt = now
		rec.UpdatedAt = now
		return rec, nil
	}
	if err != nil {
		s.logger.Error(
			"idv_status_provider_failed",
			zap.String("provider", s.provider.Name()),
			zap.String("verification_id", rec.VerificationID),
			zap.Error(err),
		)
		// Surface what we have locally rather than failing the request.
		return rec, nil
	}

	if status.Status == rec.Status {
		return rec, nil
	}

	completedMs := int64(0)
	if !status.CompletedAt.IsZero() {
		completedMs = status.CompletedAt.UnixMilli()
	}
	updatedMs := s.clock().UnixMilli()
	if err := s.repo(ctx).UpdateIdentityVerificationStatus(
		ctx, rec.VerificationID, status.Status, status.RejectionReason, completedMs, updatedMs,
	); err != nil {
		return nil, fmt.Errorf("idv: update status: %w", err)
	}
	rec.Status = status.Status
	rec.RejectionReason = status.RejectionReason
	rec.CompletedAt = completedMs
	rec.UpdatedAt = updatedMs

	// On approval, mark the user as IDV-verified so login gates can
	// authorize them. Errors here are logged but not surfaced to the
	// client: the verification record itself is already approved, and
	// a stale user.idv_verified will resolve on the next login attempt
	// (or the next status poll).
	if status.Status == IDVStatusApproved {
		if err := s.repo(ctx).SetUserIDVVerified(ctx, rec.UserID, completedMs); err != nil {
			s.logger.Warn(
				"idv_user_flag_update_failed",
				zap.String("verification_id", rec.VerificationID),
				zap.String("user_id", rec.UserID),
				zap.Error(err),
			)
		}
	}
	return rec, nil
}

func (s *IdentityVerificationService) lookupForCaller(
	ctx context.Context,
	callerUserID, verificationID string,
) (*IdentityVerificationRecord, error) {
	if verificationID == "" {
		rec, err := s.repo(ctx).GetLatestIdentityVerificationForUser(ctx, callerUserID)
		if err != nil {
			return nil, fmt.Errorf("idv: latest: %w", err)
		}
		if rec == nil {
			return nil, ErrNotFound
		}
		return rec, nil
	}
	rec, err := s.repo(ctx).GetIdentityVerification(ctx, verificationID)
	if err != nil {
		return nil, fmt.Errorf("idv: get: %w", err)
	}
	if rec == nil {
		return nil, ErrNotFound
	}
	if rec.UserID != callerUserID {
		return nil, ErrPermissionDenied
	}
	return rec, nil
}

// BeginIdentityVerificationResult carries everything the connect
// handler needs to build a BeginIdentityVerificationResponse. The
// service layer keeps proto types out of its surface so the wiring
// is unit-testable without spinning up a Connect server.
type BeginIdentityVerificationResult struct {
	VerificationID string
	Provider       string
	SessionToken   string
	ExpiresAt      time.Time
}

func isTerminalIDVStatus(s string) bool {
	switch s {
	case IDVStatusApproved, IDVStatusRejected, IDVStatusExpired:
		return true
	default:
		return false
	}
}

func newVerificationID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// rand.Read failure means the kernel CSPRNG is unavailable —
		// returning a non-empty fallback would silently weaken
		// uniqueness, so panic and let the process restart.
		panic(fmt.Sprintf("idv: rand.Read failed: %v", err))
	}
	return "idv_" + hex.EncodeToString(buf)
}
