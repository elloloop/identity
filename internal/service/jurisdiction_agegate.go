package service

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/agegate"
)

// determinerForUser resolves the age-gate determiner that classifies u, in
// this order (server-side signals only — never IP-derived):
//
//  1. the account's stored Market, when the resolved project configures it in
//     config_json `jurisdictions.thresholds`;
//  2. the project's `jurisdictions.default`, when set;
//  3. the STRICTEST configured ceiling (highest child_max_age, tie-broken by
//     lowest adult_age) when the project configures thresholds but neither of
//     the above resolves — an unresolvable market must never drift an account
//     toward a more permissive regime;
//  4. the deployment-wide env thresholds (GATEWAY_AGEGATE_CHILD_MAX_AGE /
//     GATEWAY_AGEGATE_ADULT_AGE) when the project configures no jurisdictions
//     block at all — the pre-#462 behaviour, unchanged.
//
// When age-gating is disabled the deployment-wide no-op determiner is
// returned, so a gate-off deployment behaves byte-identically to before.
// Nothing is cached across requests: the project config arrives on the
// request scope the resolution middleware already parsed.
func (s *AuthService) determinerForUser(ctx context.Context, u *User) agegate.Determiner {
	return determinerForUserWith(ctx, s.ageGate, s.logger, u)
}

// determinerForUserWith is determinerForUser with the deployment-wide
// determiner passed in, so every holder of one — the AuthService, and the
// MinorDataMinimizer shared by the profile/phone/IDV paths — resolves the
// SAME per-jurisdiction band. Two definitions of "child" in one service is
// exactly the drift #462 set out to remove.
func determinerForUserWith(
	ctx context.Context, base agegate.Determiner, logger *zap.Logger, u *User,
) agegate.Determiner {
	if base == nil || !base.Enabled() {
		return base
	}
	scope := ProjectScopeFromContext(ctx)
	if scope == nil || !scope.Jurisdictions.configured() {
		return base
	}
	t := resolveJurisdictionThresholds(scope.Jurisdictions, u)
	d, err := agegate.NewThreshold(t.ChildMaxAge, t.AdultAge)
	if err != nil {
		// Unreachable for config parsed through ParseProjectConfig (it rejects
		// a pair violating 0 <= child_max < adult), but never fail open: fall
		// back to the strictest configured ceiling, then the env thresholds.
		if logger == nil {
			logger = zap.NewNop()
		}
		logger.Warn("jurisdiction_thresholds_invalid_falling_back",
			zap.Int("child_max_age", t.ChildMaxAge), zap.Int("adult_age", t.AdultAge), zap.Error(err))
		if strict, ok := scope.Jurisdictions.strictest(); ok {
			if sd, serr := agegate.NewThreshold(strict.ChildMaxAge, strict.AdultAge); serr == nil {
				return sd
			}
		}
		return base
	}
	return d
}

// resolveJurisdictionThresholds applies the market → project-default →
// strictest-ceiling precedence. The caller guarantees j.configured().
func resolveJurisdictionThresholds(j ProjectJurisdictionsConfig, u *User) JurisdictionThresholds {
	if u != nil && u.Market != "" {
		if t, ok := j.thresholdFor(u.Market); ok {
			return t
		}
	}
	if j.Default != "" {
		if t, ok := j.thresholdFor(j.Default); ok {
			return t
		}
	}
	// strictest() always finds an entry in a configured block.
	t, _ := j.strictest()
	return t
}

// resolvedMarketFor returns the market code u classifies under at this
// moment: the account's stored market when the project configures it, else
// the project's configured default, else "" when no jurisdictions block
// applies. It is the value stamped onto a parental-consent record at grant
// time so the artifact says which jurisdiction's thresholds it proves
// consent against.
func (s *AuthService) resolvedMarketFor(ctx context.Context, u *User) string {
	scope := ProjectScopeFromContext(ctx)
	if scope == nil || !scope.Jurisdictions.configured() {
		return ""
	}
	if u != nil && u.Market != "" {
		if _, ok := scope.Jurisdictions.thresholdFor(u.Market); ok {
			return normalizeJurisdictionCode(u.Market)
		}
	}
	return scope.Jurisdictions.Default
}

// validateAccountMarket rejects a market that names no configured
// jurisdiction threshold, when the project configures any. A market supplied
// for a project with no jurisdictions block is inert metadata and stores
// fine — the env thresholds keep classifying the account, and the value
// becomes meaningful if the project later configures thresholds.
func (s *AuthService) validateAccountMarket(ctx context.Context, market string) error {
	if market == "" {
		return nil // no market supplied: nothing to validate
	}
	scope := ProjectScopeFromContext(ctx)
	if scope == nil || !scope.Jurisdictions.configured() {
		return nil
	}
	if _, ok := scope.Jurisdictions.thresholdFor(market); !ok {
		return fmt.Errorf("%w: market %q is not one of this project's configured jurisdictions", ErrInvalidArgument, market)
	}
	return nil
}
