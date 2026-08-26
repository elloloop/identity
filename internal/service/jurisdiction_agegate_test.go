package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/agegate"
)

// The jurisdiction policies under test: IN carries the DPDP under-18 child
// ceiling (child_max_age 17), US the COPPA under-13 one (child_max_age 12).
// Both blobs hold access open so the default-DENY access gate never fires —
// these tests are about age classification.
const (
	jurisdictionsJSON = `{"access":{"mode":"open"},"jurisdictions":{` +
		`"default":"IN","thresholds":{` +
		`"IN":{"child_max_age":17,"adult_age":18},` +
		`"US":{"child_max_age":12,"adult_age":18}}}}`
	// No default: BR ties IN on child_max_age (17) with a HIGHER adult_age, so
	// the strictest-ceiling tie-break (lowest adult_age) resolves to IN's pair.
	jurisdictionsNoDefaultJSON = `{"access":{"mode":"open"},"jurisdictions":{"thresholds":{` +
		`"IN":{"child_max_age":17,"adult_age":18},` +
		`"US":{"child_max_age":12,"adult_age":18},` +
		`"BR":{"child_max_age":17,"adult_age":21}}}}`
)

// jurisdictionScope parses configJSON exactly as the control-plane resolver
// does and returns a context carrying the resulting project scope, so tests
// exercise the real parse + canonicalization rather than a hand-built policy.
func jurisdictionScope(t *testing.T, configJSON string) context.Context {
	t.Helper()
	cfg, err := ParseProjectConfig(configJSON)
	require.NoError(t, err)
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID:     "project-a",
		Access:        cfg.Access,
		Products:      cfg.Products,
		Jurisdictions: cfg.Jurisdictions,
	})
}

// bandAt classifies a DOB (in whole years at the fixed test clock) under the
// determiner the resolution produces for (ctx, user).
func bandAt(ctx context.Context, t *testing.T, svc *AuthService, u *User, ageYears int) agegate.AgeBand {
	t.Helper()
	d := svc.determinerForUser(ctx, u)
	require.True(t, d.Enabled(), "test setup: age gate must be on")
	return d.Determine(dobAgeMs(ageYears), ageGateNow).Band
}

func TestDeterminerForUser_ResolutionOrder(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		configJSON string // "" = no project scope at all
		market     string
		ageYears   int
		want       agegate.AgeBand
	}{
		// 1. The stored market wins over the project default.
		{"market beats project default", jurisdictionsJSON, "US", 16, agegate.BandTeen},
		{"market IN classifies child at 16", jurisdictionsJSON, "IN", 16, agegate.BandChild},
		{"stored market casing is normalized", jurisdictionsJSON, "us", 16, agegate.BandTeen},
		// 2. No stored market → the project default applies.
		{"project default when no market", jurisdictionsJSON, "", 16, agegate.BandChild},
		// 3. An unresolvable market (or no market and no default) falls to the
		// STRICTEST configured ceiling — IN/BR tie on child_max_age 17, the
		// tie breaks to IN's lower adult_age; both classify 16 as CHILD.
		{"unknown market falls to default", jurisdictionsJSON, "BR", 16, agegate.BandChild},
		{"unknown market no default falls to strictest", jurisdictionsNoDefaultJSON, "ZZ", 16, agegate.BandChild},
		{"no market no default falls to strictest", jurisdictionsNoDefaultJSON, "", 16, agegate.BandChild},
		// 4. No jurisdictions block → the env thresholds (12/18) classify.
		{"env fallback without any scope", "", "US", 16, agegate.BandTeen},
		{"env fallback when block absent", `{"access":{"mode":"open"}}`, "US", 16, agegate.BandTeen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := newTestAuthService(t, newFakeRepo())
			enableAgeGate(t, svc, false)
			ctx := context.Background()
			if tc.configJSON != "" {
				ctx = jurisdictionScope(t, tc.configJSON)
			}
			got := bandAt(ctx, t, svc, &User{Market: tc.market}, tc.ageYears)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestJurisdictionPin_Age16_ChildIN_TeenUS is the issue's acceptance pin: the
// SAME date of birth (age 16 at the fixed clock) classifies CHILD under IN's
// under-18 ceiling and TEEN under US's under-13 one.
func TestJurisdictionPin_Age16_ChildIN_TeenUS(t *testing.T) {
	t.Parallel()
	svc := newTestAuthService(t, newFakeRepo())
	enableAgeGate(t, svc, false)
	ctx := jurisdictionScope(t, jurisdictionsJSON)

	assert.Equal(t, agegate.BandChild, bandAt(ctx, t, svc, &User{Market: "IN"}, 16))
	assert.Equal(t, agegate.BandTeen, bandAt(ctx, t, svc, &User{Market: "US"}, 16))
}

func TestDeterminerForUser_GateDisabled_IsNoop(t *testing.T) {
	t.Parallel()
	// Gate off: even a fully-configured jurisdictions block is inert — the
	// no-op determiner keeps behaviour byte-identical to a deployment without
	// the feature.
	svc := newTestAuthService(t, newFakeRepo())
	ctx := jurisdictionScope(t, jurisdictionsJSON)
	assert.False(t, svc.determinerForUser(ctx, &User{Market: "IN"}).Enabled())

	u := &User{Market: "IN", DateOfBirthMs: dobAgeMs(8)}
	svc.stampAgeBand(ctx, u)
	assert.False(t, u.IsMinor)
	assert.Empty(t, u.AgeBand)
}

func TestPasswordSignup_Jurisdiction_MarketStoredAndGated(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		configJSON  string
		market      string
		ageYears    int
		wantStatus  string
		wantBand    string
		wantTokens  bool
		wantStored  string
		wantSignErr error
	}{
		// The pin, through the real signup path: age 16 is CHILD in IN
		// (pending, no tokens) and TEEN in US (active, tokens).
		{"IN child at 16 is gated", jurisdictionsJSON, "IN", 16, StatusPendingParentalConsent, "CHILD", false, "IN", nil},
		{"US teen at 16 signs in", jurisdictionsJSON, "US", 16, StatusActive, "TEEN", true, "US", nil},
		// A mixed-case market is canonicalized before storage and lookup.
		{"market canonicalized", jurisdictionsJSON, " in ", 16, StatusPendingParentalConsent, "CHILD", false, "IN", nil},
		// No market at signup → the project default (IN) classifies.
		{"project default applies at signup", jurisdictionsJSON, "", 16, StatusPendingParentalConsent, "CHILD", false, "", nil},
		// A market the project does not configure is rejected outright rather
		// than silently classified under the strictest ceiling at signup.
		{"unconfigured market rejected", jurisdictionsJSON, "BR", 16, "", "", false, "", ErrInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			enableAgeGate(t, svc, false)
			ctx := jurisdictionScope(t, tc.configJSON)

			res, err := svc.PasswordSignup(ctx, "user@example.com", strongPW, "User", "", dobAgeMs(tc.ageYears), tc.market)
			if tc.wantSignErr != nil {
				require.ErrorIs(t, err, tc.wantSignErr)
				stored, lerr := repo.FindUserByEmail(context.Background(), "user@example.com")
				require.NoError(t, lerr)
				assert.Nil(t, stored, "a rejected market must not create the account")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, res.User.Status)
			assert.Equal(t, tc.wantBand, res.User.AgeBand)
			assert.Equal(t, tc.wantStored, res.User.Market)
			if tc.wantTokens {
				assert.NotEmpty(t, res.AccessToken)
			} else {
				assert.Empty(t, res.AccessToken)
			}
			// The stored row carries the canonical market and the DOB.
			stored, lerr := repo.FindUserByEmail(context.Background(), "user@example.com")
			require.NoError(t, lerr)
			require.NotNil(t, stored)
			assert.Equal(t, tc.wantStored, stored.Market)
			assert.Equal(t, tc.wantStatus, stored.Status)
		})
	}
}

func TestPasswordSignup_MarketStored_GateOff(t *testing.T) {
	t.Parallel()
	// Gate off, no jurisdictions configured: the market is stored as inert
	// metadata and classification stays exactly as before.
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	res, err := svc.PasswordSignup(context.Background(), "kid@example.com", strongPW, "Kid", "", dobAgeMs(8), "us")
	require.NoError(t, err)
	assert.Equal(t, StatusActive, res.User.Status)
	assert.Empty(t, res.User.AgeBand)
	assert.Equal(t, "US", res.User.Market)
	assert.NotEmpty(t, res.AccessToken)
}

// TestProductAgeGate_IndependentOfJurisdiction pins that the per-product
// minimum-age-band guardrail (#400) and the per-jurisdiction classification
// (#462) evaluate INDEPENDENTLY: the jurisdiction decides the band, the
// product decides whether that band may enter. A 16-year-old is TEEN under US
// thresholds — past the account-creation gate, but still below an
// adult-minimum product's door.
func TestProductAgeGate_IndependentOfJurisdiction(t *testing.T) {
	t.Parallel()
	const combinedJSON = `{"access":{"mode":"open"},` +
		`"products":{"product-b":{"minimum_age_band":"adult"},"product-a":{}},` +
		`"jurisdictions":{"default":"US","thresholds":{` +
		`"IN":{"child_max_age":17,"adult_age":18},` +
		`"US":{"child_max_age":12,"adult_age":18}}}}`

	newSvc := func(t *testing.T) (*AuthService, *fakeRepo) {
		t.Helper()
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		enableAgeGate(t, svc, false)
		return svc, repo
	}

	t.Run("US teen at 16 is below an adult-minimum product", func(t *testing.T) {
		svc, _ := newSvc(t)
		ctx := WithProduct(jurisdictionScope(t, combinedJSON), "product-b")
		_, err := svc.PasswordSignup(ctx, "teen@example.com", strongPW, "Teen", "", dobAgeMs(16), "US")
		require.ErrorIs(t, err, ErrProductAgeRestricted)
	})

	t.Run("US teen at 16 enters an unrestricted product", func(t *testing.T) {
		svc, _ := newSvc(t)
		ctx := WithProduct(jurisdictionScope(t, combinedJSON), "product-a")
		res, err := svc.PasswordSignup(ctx, "teen@example.com", strongPW, "Teen", "", dobAgeMs(16), "US")
		require.NoError(t, err)
		assert.Equal(t, "TEEN", res.User.AgeBand)
		assert.NotEmpty(t, res.AccessToken)
	})

	t.Run("IN child at 16 is gated at signup regardless of product", func(t *testing.T) {
		svc, _ := newSvc(t)
		// product-a imposes no minimum; the jurisdiction classification alone
		// (CHILD under IN) puts the account in PENDING_PARENTAL_CONSENT.
		ctx := WithProduct(jurisdictionScope(t, combinedJSON), "product-a")
		res, err := svc.PasswordSignup(ctx, "kid@example.com", strongPW, "Kid", "", dobAgeMs(16), "IN")
		require.NoError(t, err)
		assert.Equal(t, StatusPendingParentalConsent, res.User.Status)
		assert.Empty(t, res.AccessToken)
	})
}

// TestStampAgeBand_UsesResolvedMarket pins the token-issuing path: the band
// stamped at issueTokensWithSessionStart derives from the account's stored
// market, so a refresh after a market change classifies under the NEW market.
func TestStampAgeBand_UsesResolvedMarket(t *testing.T) {
	t.Parallel()
	svc := newTestAuthService(t, newFakeRepo())
	enableAgeGate(t, svc, false)
	ctx := jurisdictionScope(t, jurisdictionsJSON)

	u := &User{DateOfBirthMs: dobAgeMs(16), Market: "US"}
	svc.stampAgeBand(ctx, u)
	assert.Equal(t, "TEEN", u.AgeBand)
	assert.True(t, u.IsMinor)

	u.Market = "IN"
	svc.stampAgeBand(ctx, u)
	assert.Equal(t, "CHILD", u.AgeBand)
	assert.True(t, u.IsMinor)
}

// TestGrantParentalConsent_RecordsResolvedMarket pins that the consent record
// snapshots the market the child's classification resolved under: the stored
// market when configured, else the project's default, else "" when no
// jurisdictions block applies.
func TestGrantParentalConsent_RecordsResolvedMarket(t *testing.T) {
	t.Parallel()
	pwHash := hashPW(t, strongPW)

	grant := func(t *testing.T, ctx context.Context, childMarket string) *ParentalConsentRecord {
		t.Helper()
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		adult := seedConsentingAdult(t, repo, "adult@example.com", pwHash, adultFactors{phoneVerified: true})
		child := seedChildPendingConsent(repo, "child@example.com")
		if childMarket != "" {
			repo.mu.Lock()
			repo.users[child.ID].Market = childMarket
			repo.mu.Unlock()
		}
		rec, err := svc.GrantParentalConsent(ctx, adult.ID, child.ID, consentPolicyVersion, strongPW, "", "")
		require.NoError(t, err)
		return rec
	}

	t.Run("stored market wins", func(t *testing.T) {
		rec := grant(t, jurisdictionScope(t, jurisdictionsJSON), "IN")
		assert.Equal(t, "IN", rec.Market)
	})
	t.Run("project default when no stored market", func(t *testing.T) {
		rec := grant(t, jurisdictionScope(t, jurisdictionsJSON), "")
		assert.Equal(t, "IN", rec.Market) // jurisdictionsJSON defaults to IN
	})
	t.Run("empty without a jurisdictions block", func(t *testing.T) {
		rec := grant(t, context.Background(), "IN")
		assert.Empty(t, rec.Market)
	})
}
