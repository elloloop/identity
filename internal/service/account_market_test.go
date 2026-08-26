package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// marketSvc builds an age-gated service with an audit recorder, signed-up
// under the jurisdictions test policy (IN child_max 17, US child_max 12,
// default US), and returns the signup result alongside. ageYears pins the
// account's DOB at the fixed test clock.
func marketSvc(t *testing.T, ageYears int, market string) (*AuthService, *fakeRepo, *recordingAuditWriter, context.Context, *LoginResult) {
	t.Helper()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	enableAgeGate(t, svc, false)
	ctx := jurisdictionScope(t, jurisdictionsUSDefaultJSON)
	res, err := svc.PasswordSignup(ctx, "user@example.com", strongPW, "User", "", dobAgeMs(ageYears), market)
	require.NoError(t, err)
	return svc, repo, writer, ctx, res
}

// jurisdictionsUSDefaultJSON defaults to the permissive US ceiling so a
// signup with no market starts ungated; tests then tighten via
// SetAccountMarket.
const jurisdictionsUSDefaultJSON = `{"access":{"mode":"open"},"jurisdictions":{` +
	`"default":"US","thresholds":{` +
	`"IN":{"child_max_age":17,"adult_age":18},` +
	`"US":{"child_max_age":12,"adult_age":18}}}}`

func TestSetAccountMarket_StoresAndAudits(t *testing.T) {
	t.Parallel()
	svc, repo, writer, ctx, res := marketSvc(t, 30, "US")

	u, err := svc.SetAccountMarket(ctx, res.User.ID, "in")
	require.NoError(t, err)
	// The stored value is canonicalized; an adult under US stays an adult
	// under IN, so no status effect.
	assert.Equal(t, "IN", u.Market)
	assert.Equal(t, StatusActive, u.Status)
	assert.Equal(t, "ADULT", u.AgeBand)

	stored, err := repo.GetUser(context.Background(), res.User.ID)
	require.NoError(t, err)
	assert.Equal(t, "IN", stored.Market)

	assert.Equal(t, 1, writer.countByEventTypeAndDetail("account_market_changed", "new_market", "IN"))
	assert.Equal(t, 1, writer.countByEventTypeAndDetail("account_market_changed", "old_market", "US"))
}

func TestSetAccountMarket_Validation(t *testing.T) {
	t.Parallel()
	svc, _, _, ctx, res := marketSvc(t, 30, "US")

	_, err := svc.SetAccountMarket(ctx, res.User.ID, "")
	assert.ErrorIs(t, err, ErrInvalidArgument)

	// A market the project does not configure is rejected, and the stored
	// market is untouched.
	_, err = svc.SetAccountMarket(ctx, res.User.ID, "BR")
	assert.ErrorIs(t, err, ErrInvalidArgument)

	_, err = svc.SetAccountMarket(ctx, "", "IN")
	assert.ErrorIs(t, err, ErrUnauthenticated)

	_, err = svc.SetAccountMarket(ctx, "no-such-user", "IN")
	assert.ErrorIs(t, err, ErrNotFound)
}

// TestSetAccountMarket_RegateToChild is the re-gating pin: an account that
// was a US TEEN becomes an IN CHILD, lands in PENDING_PARENTAL_CONSENT, and
// its live sessions die at once — a refresh with the pre-change token fails.
func TestSetAccountMarket_RegateToChild(t *testing.T) {
	t.Parallel()
	// Age 13: TEEN under US (child_max 12), CHILD under IN (child_max 17).
	svc, repo, _, ctx, res := marketSvc(t, 13, "US")
	require.Equal(t, StatusActive, res.User.Status)
	require.NotEmpty(t, res.RefreshToken)

	u, err := svc.SetAccountMarket(ctx, res.User.ID, "IN")
	require.NoError(t, err)
	assert.Equal(t, StatusPendingParentalConsent, u.Status)
	assert.Equal(t, "CHILD", u.AgeBand)

	stored, err := repo.GetUser(context.Background(), res.User.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusPendingParentalConsent, stored.Status)

	// The re-gate revoked every session: the signup-issued refresh token no
	// longer rotates.
	_, _, _, err = svc.RefreshToken(ctx, res.RefreshToken, "", "")
	assert.ErrorIs(t, err, ErrUnauthenticated)
}

// TestSetAccountMarket_RegateSkipsConsentedChild pins that an active consent
// record still covers the account: the market change re-derives the band but
// does not re-gate.
func TestSetAccountMarket_RegateSkipsConsentedChild(t *testing.T) {
	t.Parallel()
	svc, repo, _, ctx, res := marketSvc(t, 13, "US")

	repo.mu.Lock()
	repo.parentalConsents["pc-1"] = &ParentalConsentRecord{
		ConsentID: "pc-1", ChildUserID: res.User.ID, ConsentingUserID: "adult-1",
		PolicyVersion: "notice-v1", Factors: "verified_phone", SteppedUp: true, GrantedAt: 1,
	}
	repo.mu.Unlock()

	u, err := svc.SetAccountMarket(ctx, res.User.ID, "IN")
	require.NoError(t, err)
	assert.Equal(t, "CHILD", u.AgeBand)
	assert.Equal(t, StatusActive, u.Status, "a consented child keeps its active status")

	_, _, _, err = svc.RefreshToken(ctx, res.RefreshToken, "", "")
	assert.NoError(t, err, "sessions survive when consent covers the re-gate")
}

// TestSetAccountMarket_LeavingChildBandKeepsStatus pins the asymmetry: moving
// OUT of the child band never reactivates an account — guardian-granted
// rights come from guardian edges checked at guard time, not from the band.
func TestSetAccountMarket_LeavingChildBandKeepsStatus(t *testing.T) {
	t.Parallel()
	// Age 13 signed up under IN: CHILD at signup, pending from creation.
	svc, _, _, ctx, res := marketSvc(t, 13, "IN")
	require.Equal(t, StatusPendingParentalConsent, res.User.Status)

	u, err := svc.SetAccountMarket(ctx, res.User.ID, "US")
	require.NoError(t, err)
	assert.Equal(t, "TEEN", u.AgeBand)
	assert.Equal(t, StatusPendingParentalConsent, u.Status,
		"leaving the child band must not self-activate the account")
}

// TestSetAccountMarket_GateDisabled_StoresOnly pins the gate-off contract:
// the market is stored and audited, no band is derived, no status changes.
func TestSetAccountMarket_GateDisabled_StoresOnly(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	writer := newRecordingAuditWriter()
	svc := newTestAuthServiceWithAudit(t, repo, writer)
	// No enableAgeGate: the gate is off. No project scope: any market stores.
	res, err := svc.PasswordSignup(context.Background(), "user@example.com", strongPW, "User", "", 0, "")
	require.NoError(t, err)

	u, err := svc.SetAccountMarket(context.Background(), res.User.ID, "IN")
	require.NoError(t, err)
	assert.Equal(t, "IN", u.Market)
	assert.Equal(t, StatusActive, u.Status)
	assert.Empty(t, u.AgeBand)
	assert.Equal(t, 1, writer.countByEventTypeAndDetail("account_market_changed", "new_market", "IN"))
}
