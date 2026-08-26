package service

import (
	"context"
	"fmt"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/audit"
)

// SetAccountMarket changes the jurisdiction/market code the CALLER's own
// account classifies under, audits the change, and re-evaluates the account's
// age band immediately under the new market's thresholds.
//
// It is SELF-SERVICE, so it is refused for an account under guardianship. A
// managed account's market decides which jurisdiction's child ceiling
// classifies it, and the band decides whether its guardian still holds
// management rights — so a self-declared market would let the managed party
// unilaterally revoke the manager's authority by naming a jurisdiction whose
// adult age it has already passed. The jurisdiction of a managed account is
// a guardian's fact to state, not the account holder's.
//
// Re-gating rule: when the change moves the account INTO the child band and
// no active parental consent is on file, the account is set to
// PENDING_PARENTAL_CONSENT and every session is revoked at once — the new
// market's stricter ceiling applies from the change, not from the next login.
// The reverse is deliberately NOT symmetric: an account whose new market
// moves it OUT of the child band keeps its current status. Becoming a child
// is a fact about the jurisdiction; leaving the band confers no rights by
// itself — guardian-granted rights are conferred by guardian edges, checked
// at guard time (see the guardian-management epic), not by the band stamped
// here.
//
// With age-gating disabled the market is stored and audited but has no status
// effect, and no band is derived.
func (s *AuthService) SetAccountMarket(ctx context.Context, userID, market string) (*User, error) {
	if userID == "" {
		return nil, ErrUnauthenticated
	}
	market = normalizeJurisdictionCode(market)
	if market == "" {
		return nil, fmt.Errorf("%w: market is required", ErrInvalidArgument)
	}
	if err := s.validateAccountMarket(ctx, market); err != nil {
		return nil, err
	}

	repo := s.repo(ctx)
	u, err := repo.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("fetch user: %w", err)
	}
	if u == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	// An account someone else manages cannot re-declare its own jurisdiction:
	// the market feeds the band, and the band is what ends guardianship.
	guardians, err := repo.ListGuardiansOfChild(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("check guardians: %w", err)
	}
	if len(guardians) > 0 {
		s.audit.Log(
			ctx, audit.EventAccountMarketChanged,
			audit.WithActor(userID), audit.WithTarget(userID), audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"step": "under_guardianship", "new_market": market}),
		)
		return nil, fmt.Errorf(
			"%w: an account under guardianship cannot change its own market", ErrPermissionDenied,
		)
	}

	old := u.Market
	now := s.nowMs()
	if err := repo.UpdateUser(ctx, userID, map[string]any{
		"market":     market,
		"updated_at": now,
	}); err != nil {
		return nil, fmt.Errorf("store market: %w", err)
	}
	u.Market = market
	u.UpdatedAt = msToTime(now)

	s.audit.Log(
		ctx, audit.EventAccountMarketChanged,
		audit.WithActor(userID), audit.WithTarget(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"old_market": old, "new_market": market}),
	)

	if !s.ageGate.Enabled() {
		return u, nil
	}

	s.stampAgeBand(ctx, u)
	if u.AgeBand != string(agegate.BandChild) || !isActiveConsentingAccount(u.Status) {
		return u, nil
	}
	// The account newly classifies as CHILD. An already-consented child keeps
	// its active status (the consent record still covers it); an unconsented
	// one is re-gated and cut off immediately.
	hasConsent, err := repo.GetActiveParentalConsentForChild(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("check active parental consent: %w", err)
	}
	if hasConsent != nil {
		return u, nil
	}
	if err := repo.UpdateUser(ctx, userID, map[string]any{
		"status":     StatusPendingParentalConsent,
		"updated_at": now,
	}); err != nil {
		return nil, fmt.Errorf("re-gate account: %w", err)
	}
	if err := revokeAllUserSessions(ctx, repo, userID, now); err != nil {
		return nil, fmt.Errorf("revoke sessions: %w", err)
	}
	u.Status = StatusPendingParentalConsent
	return u, nil
}
