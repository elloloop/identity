package service

import (
	"context"

	"go.uber.org/zap"
)

// enforceProductAgeGate refuses to issue a session when the authenticated
// account's age band is below the minimum the requested product configures.
// One account authenticates across every product in the pool, so a product's
// audience rating can only be a real guardrail if it is checked here, at the
// door, rather than assumed from store listing copy.
//
// It runs at issueTokensWithSessionStart — the single point every token pair is
// minted from, initial login and refresh alike — for two reasons. It is
// unconditionally AFTER authentication succeeded, so a denial can never
// disclose whether an email exists. And it cannot be forgotten: a session-
// issuing path added later is gated by construction rather than by remembering
// to call a guard.
//
// Fail direction — FAIL OPEN, deliberately, and the inverse of the access-mode
// gate:
//
//   - No scope, no product, no configured minimum → permit. The gate exists to
//     stop accounts KNOWN to be too young; absence of policy is not suspicion.
//   - AGE_BAND_UNSPECIFIED (an account with no date of birth on file, or a
//     deployment with age-gating switched off) → permit. Refusing unknown ages
//     would force every product to collect a birthdate from every adult, which
//     is the worse privacy outcome; child accounts always have a date of birth
//     by construction (the kid signup flows require one), so the gate still
//     catches exactly the population it exists for.
func (s *AuthService) enforceProductAgeGate(ctx context.Context, user *User) error {
	scope := ProjectScopeFromContext(ctx)
	if scope == nil || user == nil {
		return nil
	}
	product := ProductFromContext(ctx)
	minimum := scope.Products.minimumAgeBand(product)
	if ageBandPermits(minimum, user.AgeBand) {
		return nil
	}
	s.logger.Info("product_age_restricted",
		zap.String("project_id", s.projectID(ctx)),
		zap.String("product", product),
		zap.String("minimum_age_band", minimum),
		zap.String("age_band", user.AgeBand))
	return ErrProductAgeRestricted
}

// ageBandPermits reports whether an account classified into band may be issued
// a session for a product whose minimum is minimum. It is a pure decision
// function (no I/O, no receiver) so the whole policy matrix is unit-testable in
// isolation.
//
// Both arguments are compared through minimumAgeBandRank, where an unrecognized
// or empty value ranks 0 and passes: rank 0 on the minimum is "product imposes
// nothing", rank 0 on the account is "age unknown". band arrives as the
// agegate.Band* spelling stamped onto User.AgeBand ("CHILD"/"TEEN"/"ADULT"/""),
// so it is normalized to the lower-cased config spelling before the lookup.
func ageBandPermits(minimum, band string) bool {
	required := minimumAgeBandRank[minimum]
	if required == 0 {
		return true
	}
	actual := minimumAgeBandRank[normalizeProductSlug(band)]
	if actual == 0 {
		return true
	}
	return actual >= required
}
