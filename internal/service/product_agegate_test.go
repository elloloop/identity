package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/secretcrypto"
	"github.com/elloloop/identity/pkg/totp"
)

// The product slugs the guardrail matrix exercises: one restricted product and
// one the same config leaves unrestricted, so every case also proves the policy
// is scoped to the slug rather than applied project-wide.
const (
	restrictedProduct   = "product-b"
	unrestrictedProduct = "product-a"
)

// The three policies an operator can be in for a product, as config_json. Every
// blob sets access mode "open" because the access gate is default-DENY and would
// otherwise refuse before the age gate is ever reached — these tests are about
// the age gate, so access is held open throughout.
const (
	noProductPolicyJSON = `{"access":{"mode":"open"}}`
	teenMinimumJSON     = `{"access":{"mode":"open"},"products":{"product-b":{"minimum_age_band":"teen"},"product-a":{}}}`
	adultMinimumJSON    = `{"access":{"mode":"open"},"products":{"product-b":{"minimum_age_band":"adult"},"product-a":{}}}`
)

const productAgePassword = "S3cure!Passw0rd"

// productScope parses configJSON exactly as the control-plane resolver does and
// returns a context carrying the resulting project scope plus the product slug
// the product-resolution middleware would have stamped from X-Product, so tests
// exercise the real parse + canonicalization rather than a hand-built policy.
func productScope(t *testing.T, configJSON, product string) context.Context {
	t.Helper()
	cfg, err := ParseProjectConfig(configJSON)
	require.NoError(t, err)
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "project-a",
		Access:    cfg.Access,
		Products:  cfg.Products,
		Anonymous: cfg.Anonymous,
	})
	return WithProduct(ctx, product)
}

// newProductAgeSvc builds an auth service with age-gating ON and a fixed clock,
// so a seeded date of birth derives into a deterministic band.
func newProductAgeSvc(t *testing.T) (*AuthService, *fakeRepo, *recordingTransport) {
	t.Helper()
	svc, repo, rec := newAuthSvcWithMailer(t)
	enableAgeGate(t, svc, false)
	// The mailer-backed constructor wires no OAuth registry and no magic-link
	// return allowlist; both are needed here because one service drives every
	// issuing path, OAuth and magic-link included.
	svc.oauthResolver = newOAuthResolver(svc.cfg.DefaultProjectID, defaultTestOAuthRegistry(), svc.cfg.OAuthHubSharing, zap.NewNop())
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	return svc, repo, rec
}

// seedUserAged seeds an ACTIVE account whose stored date of birth derives into
// the band under test. dobMs 0 is the "never gave a birthdate" account, which
// derives to the unspecified band.
func seedUserAged(t *testing.T, repo *fakeRepo, addr string, dobMs int64) *User {
	t.Helper()
	u := seedUser(repo, addr, hashPW(t, productAgePassword), "active")
	repo.mu.Lock()
	repo.users[u.ID].DateOfBirthMs = dobMs
	repo.mu.Unlock()
	return u
}

// ── The policy decision, in isolation ────────────────────────────────────

// ageBandPermits is the whole guardrail matrix (configured minimum × derived
// band) in one table. Everything below drives the same predicate through real
// RPCs; this proves the predicate itself.
func TestAgeBandPermits_Matrix(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		minimum string
		band    string
		permit  bool
	}{
		{"no_minimum_child", "", "CHILD", true},
		{"no_minimum_unknown", "", "", true},
		{"child_minimum_child", MinimumAgeBandChild, "CHILD", true},
		{"teen_minimum_child", MinimumAgeBandTeen, "CHILD", false},
		{"teen_minimum_teen", MinimumAgeBandTeen, "TEEN", true},
		{"teen_minimum_adult", MinimumAgeBandTeen, "ADULT", true},
		{"teen_minimum_unknown", MinimumAgeBandTeen, "", true},
		{"adult_minimum_child", MinimumAgeBandAdult, "CHILD", false},
		{"adult_minimum_teen", MinimumAgeBandAdult, "TEEN", false},
		{"adult_minimum_adult", MinimumAgeBandAdult, "ADULT", true},
		{"adult_minimum_unknown", MinimumAgeBandAdult, "", true},
		// A band spelled as config does rather than as the stamp does still
		// compares, because both sides normalize.
		{"adult_minimum_lowercase_band", MinimumAgeBandAdult, "child", false},
		// An unrecognized minimum cannot reach the predicate through
		// ParseProjectConfig (it rejects the write), but the predicate itself
		// still fails open rather than denying everyone.
		{"unrecognized_minimum", "grown-up", "CHILD", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.permit, ageBandPermits(tc.minimum, tc.band))
		})
	}
}

func TestEnforceProductAgeGate_NoScopeOrNoUser_Permits(t *testing.T) {
	t.Parallel()
	svc, _, _ := newProductAgeSvc(t)
	child := &User{AgeBand: "CHILD"}
	// No scope in context (a direct service call / non-project deployment).
	require.NoError(t, svc.enforceProductAgeGate(WithProduct(context.Background(), restrictedProduct), child))
	// A scope but no user is not a decision this gate can make.
	require.NoError(t, svc.enforceProductAgeGate(productScope(t, adultMinimumJSON, restrictedProduct), nil))
}

// ── Config parsing + validation ──────────────────────────────────────────

func TestParseProjectConfig_Products_Bands(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(`{"products":{"product-b":{"minimum_age_band":"teen"},` +
		`"product-c":{},"Product-A":{"minimum_age_band":"  ADULT "}}}`)
	require.NoError(t, err)
	assert.Equal(t, MinimumAgeBandTeen, cfg.Products.minimumAgeBand("product-b"))
	assert.Equal(t, "", cfg.Products.minimumAgeBand("product-c"))
	// Slugs and bands are canonicalized at parse time, so a mixed-case config
	// matches the lower-cased slug the middleware stamps.
	assert.Equal(t, MinimumAgeBandAdult, cfg.Products.minimumAgeBand("product-a"))
	// An unconfigured product imposes nothing.
	assert.Equal(t, "", cfg.Products.minimumAgeBand("product-d"))
}

func TestParseProjectConfig_Products_OmittedIsNoPolicy(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(`{"access":{"mode":"open"}}`)
	require.NoError(t, err)
	assert.Nil(t, cfg.Products)
	assert.Equal(t, "", cfg.Products.minimumAgeBand(restrictedProduct))
}

// A malformed products block is rejected at config-write time (the admin RPC
// validates through ParseProjectConfig) rather than being served as
// "unrestricted" — a typo'd band must fail loudly, not silently drop a guardrail.
func TestParseProjectConfig_Products_Validation(t *testing.T) {
	t.Parallel()
	for name, blob := range map[string]string{
		"unrecognized_band": `{"products":{"product-b":{"minimum_age_band":"grown-up"}}}`,
		"typo_band":         `{"products":{"product-b":{"minimum_age_band":"chid"}}}`,
		"proto_enum_band":   `{"products":{"product-b":{"minimum_age_band":"AGE_BAND_TEEN"}}}`,
		"numeric_band":      `{"products":{"product-b":{"minimum_age_band":"18"}}}`,
		"blank_slug":        `{"products":{"  ":{"minimum_age_band":"teen"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseProjectConfig(blob)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "parse project config")
		})
	}
}

func TestParseProjectConfig_Products_AcceptsEveryBand(t *testing.T) {
	t.Parallel()
	for _, band := range []string{MinimumAgeBandChild, MinimumAgeBandTeen, MinimumAgeBandAdult} {
		cfg, err := ParseProjectConfig(`{"products":{"product-b":{"minimum_age_band":"` + band + `"}}}`)
		require.NoError(t, err, "band %q", band)
		assert.Equal(t, band, cfg.Products.minimumAgeBand("product-b"))
	}
}

// ── Every session-issuing path × band × policy ───────────────────────────

// productAgeBand is one account age under test, as the date of birth that
// derives into it. The unspecified band is an account that never gave one.
type productAgeBand struct {
	name  string
	dobMs int64
}

func productAgeBands() []productAgeBand {
	return []productAgeBand{
		{"child", dobAgeMs(8)},
		{"teen", dobAgeMs(15)},
		{"adult", dobAgeMs(30)},
		{"unspecified", 0},
	}
}

// productAgePolicy is one operator configuration and the bands it refuses.
type productAgePolicy struct {
	name       string
	configJSON string
	refuses    map[string]bool
}

func productAgePolicies() []productAgePolicy {
	return []productAgePolicy{
		{"no_policy", noProductPolicyJSON, map[string]bool{}},
		{"teen_minimum", teenMinimumJSON, map[string]bool{"child": true}},
		{"adult_minimum", adultMinimumJSON, map[string]bool{"child": true, "teen": true}},
	}
}

// productAgePath drives ONE session-issuing path to completion for an account
// whose date of birth is dobMs, and returns whatever that path returned. Each
// builds its own service so a path with special wiring (passkey vectors, TOTP
// credentials) stays self-contained.
type productAgePath struct {
	name  string
	issue func(t *testing.T, ctx context.Context, dobMs int64) error
}

// productAgeIssuingPaths enumerates every path that authenticates an EXISTING
// account and mints a session for it. The two account-CREATING paths are
// covered separately (their band comes from the flow, not from a stored
// account), as is the QR approval/poll split.
func productAgeIssuingPaths() []productAgePath {
	return []productAgePath{
		{"password_login", func(t *testing.T, ctx context.Context, dobMs int64) error {
			t.Helper()
			svc, repo, _ := newProductAgeSvc(t)
			seedUserAged(t, repo, "user@example.com", dobMs)
			_, err := svc.PasswordLogin(ctx, "user@example.com", productAgePassword, "1.2.3.4", "agent")
			return err
		}},
		{"email_code_redeem", func(t *testing.T, ctx context.Context, dobMs int64) error {
			t.Helper()
			svc, repo, rec := newProductAgeSvc(t)
			seedUserAged(t, repo, "user@example.com", dobMs)
			require.NoError(t, svc.RequestEmailLoginCode(ctx, "user@example.com"))
			require.Len(t, rec.Sent(), 1)
			code := extractCodeFromEmail(t, rec.Sent()[0].Text)
			_, err := svc.VerifyEmailLoginCode(ctx, "user@example.com", code, "1.2.3.4", "agent")
			return err
		}},
		{"magic_link_redeem", func(t *testing.T, ctx context.Context, dobMs int64) error {
			t.Helper()
			svc, repo, rec := newProductAgeSvc(t)
			seedUserAged(t, repo, "user@example.com", dobMs)
			require.NoError(t, svc.RequestMagicLink(ctx, "user@example.com", "https://app.test/cb"))
			require.Len(t, rec.Sent(), 1)
			token := extractTokenFromLink(t, rec.Sent()[0].Text)
			_, err := svc.RedeemMagicLink(ctx, token, "1.2.3.4", "agent")
			return err
		}},
		{"oauth_redeem", func(t *testing.T, ctx context.Context, dobMs int64) error {
			t.Helper()
			svc, repo, _ := newProductAgeSvc(t)
			seedUserAged(t, repo, "user@example.com", dobMs)
			_, err := svc.OAuthLogin(ctx, OAuthLoginParams{
				Code:        fakeOAuthCode("user@example.com", "User", "", "google"),
				Provider:    "google",
				RedirectURI: "https://app/cb",
			})
			return err
		}},
		{"hosted_oauth_redeem", func(t *testing.T, ctx context.Context, dobMs int64) error {
			t.Helper()
			svc, repo, _ := newProductAgeSvc(t)
			seedUserAged(t, repo, "user@example.com", dobMs)
			begin, err := svc.BeginHostedOAuth(ctx, "google",
				"https://identity.test/oauth/callback/google", "https://app.test/finish", "csrf-1", "")
			require.NoError(t, err)
			// The callback completes an OAuthLogin internally (and discards its
			// tokens), so the guardrail can refuse here — before a one-time code
			// is ever minted — or at the redeem. Either is the path's answer.
			cb, err := svc.CompleteHostedOAuth(ctx, "google",
				fakeOAuthCode("user@example.com", "User", "", "google"),
				stateTokenFromAuthURL(t, begin.AuthorizationURL), "", "1.2.3.4", "agent", []string{"csrf-1"})
			if err != nil {
				return err
			}
			_, err = svc.RedeemOAuthCode(ctx, cb.Code, "1.2.3.4", "agent")
			return err
		}},
		{"passkey_login", func(t *testing.T, ctx context.Context, dobMs int64) error {
			t.Helper()
			svc, repo, rec := newPasskeyVectorSvc(t)
			enableAgeGate(t, svc, false)
			// Provision the passkey AS THE UNRESTRICTED PRODUCT — no policy under
			// test gates it — then stamp the date of birth on the account the
			// assertion will resolve to, so the login below is what the gate judges.
			provision := WithProduct(ctx, unrestrictedProduct)
			_, challengeID, err := svc.BeginPasskeySignup(provision, pkVectorEmail, "Key")
			require.NoError(t, err)
			otp := passkeySignupOTP(t, rec, pkVectorEmail)
			setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))
			signup, err := svc.CompletePasskeySignup(provision, challengeID,
				pkRegCredentialJSON(t), pkVectorEmail, otp, "Key", "1.2.3.4", "agent")
			require.NoError(t, err)
			repo.mu.Lock()
			repo.users[signup.User.ID].DateOfBirthMs = dobMs
			repo.mu.Unlock()

			_, loginChallengeID, err := svc.BeginPasskeyLogin(ctx, pkVectorEmail)
			require.NoError(t, err)
			setFakeChallengeValue(repo, loginChallengeID, pkB64URL(t, pkLoginChallengeHex))
			_, err = svc.CompletePasskeyLogin(ctx, loginChallengeID, pkAssertionCredentialJSON(t), "1.2.3.4", "agent")
			return err
		}},
		{"totp_verify", func(t *testing.T, ctx context.Context, dobMs int64) error {
			t.Helper()
			svc, repo, _ := newProductAgeSvc(t)
			u := seedUserAged(t, repo, "user@example.com", dobMs)
			challengeID := seedTotpChallenge(t, repo, u.ID)
			_, err := svc.VerifyTotp(ctx, challengeID, productAgeRecoveryCode, "1.2.3.4", "agent")
			return err
		}},
		{"qr_poll", func(t *testing.T, ctx context.Context, dobMs int64) error {
			t.Helper()
			svc, repo, _ := newProductAgeSvc(t)
			u := seedUserAged(t, repo, "user@example.com", dobMs)
			init, err := svc.InitiateQrLogin(ctx, "New Phone", "agent", "1.2.3.4")
			require.NoError(t, err)
			_, err = svc.ApproveQrLogin(ctx, init.SessionID, true, u.ID, "ApproverAgent")
			require.NoError(t, err)
			_, err = svc.PollQrLogin(ctx, init.SessionID, init.PollSecret, "1.2.3.4", "agent")
			return err
		}},
		{"accept_invitation", func(t *testing.T, ctx context.Context, dobMs int64) error {
			t.Helper()
			svc, repo, _ := newProductAgeSvc(t)
			token := seedInvitedUser(t, repo, "invitee@example.com")
			invited, err := repo.FindUserByEmail(ctx, "invitee@example.com")
			require.NoError(t, err)
			repo.mu.Lock()
			repo.users[invited.ID].DateOfBirthMs = dobMs
			repo.mu.Unlock()
			_, err = svc.AcceptInvitation(ctx, token, productAgePassword, "Invitee", "1.2.3.4", "agent")
			return err
		}},
		{"refresh", func(t *testing.T, ctx context.Context, dobMs int64) error {
			t.Helper()
			svc, repo, _ := newProductAgeSvc(t)
			seedUserAged(t, repo, "user@example.com", dobMs)
			// Mint the original session under a project with no product policy,
			// so the refresh is the FIRST place the policy under test applies.
			login, err := svc.PasswordLogin(
				WithProjectScope(ctx, scopeFromJSON(t, noProductPolicyJSON)),
				"user@example.com", productAgePassword, "1.2.3.4", "agent",
			)
			require.NoError(t, err)
			_, _, _, err = svc.RefreshToken(ctx, login.RefreshToken, "1.2.3.4", "agent")
			return err
		}},
	}
}

// TestProductAgeGate_EveryIssuingPath is the guardrail's contract: for every
// path that mints a session, an account below the product's minimum band is
// refused with the stable token, and every other combination gets in.
func TestProductAgeGate_EveryIssuingPath(t *testing.T) {
	for _, path := range productAgeIssuingPaths() {
		for _, policy := range productAgePolicies() {
			for _, band := range productAgeBands() {
				t.Run(path.name+"/"+policy.name+"/"+band.name, func(t *testing.T) {
					err := path.issue(t, productScope(t, policy.configJSON, restrictedProduct), band.dobMs)
					if policy.refuses[band.name] {
						require.ErrorIs(t, err, ErrProductAgeRestricted)
						assert.Contains(t, err.Error(), "product_age_restricted")
						return
					}
					require.NoError(t, err)
				})
			}
		}
	}
}

// The policy is per PRODUCT, not per project: the same restrictive config admits
// a child to the product it leaves unconfigured.
func TestProductAgeGate_UnrestrictedProductAdmitsChild(t *testing.T) {
	for _, path := range productAgeIssuingPaths() {
		t.Run(path.name, func(t *testing.T) {
			ctx := productScope(t, adultMinimumJSON, unrestrictedProduct)
			require.NoError(t, path.issue(t, ctx, dobAgeMs(8)))
		})
	}
}

// A request with NO X-Product header is stamped with the deployment default by
// the middleware, so it is gated as that product rather than escaping the gate.
func TestProductAgeGate_DefaultProductWhenHeaderAbsent(t *testing.T) {
	const defaultProductJSON = `{"access":{"mode":"open"},"products":{"product-a":{"minimum_age_band":"adult"}}}`

	svc, repo, _ := newProductAgeSvc(t)
	seedUserAged(t, repo, "child@example.com", dobAgeMs(8))

	// The middleware stamped the configured default (see the middleware test for
	// the header → slug mapping itself).
	ctx := productScope(t, defaultProductJSON, unrestrictedProduct)
	_, err := svc.PasswordLogin(ctx, "child@example.com", productAgePassword, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrProductAgeRestricted)

	// With no product at all in context — a deployment that configured no
	// default — nothing matches, so the request is unrestricted.
	noProduct := WithProjectScope(context.Background(), scopeFromJSON(t, defaultProductJSON))
	_, err = svc.PasswordLogin(noProduct, "child@example.com", productAgePassword, "1.2.3.4", "agent")
	require.NoError(t, err)
}

// A session issued BEFORE the product was restricted must stop refreshing once
// it is: the refresh path is the only thing standing between a policy change and
// an already-signed-in child keeping access until the refresh token expires.
func TestProductAgeGate_RefreshRefusesLaterRestrictedProduct(t *testing.T) {
	svc, repo, _ := newProductAgeSvc(t)
	seedUserAged(t, repo, "child@example.com", dobAgeMs(8))

	open := productScope(t, noProductPolicyJSON, restrictedProduct)
	login, err := svc.PasswordLogin(open, "child@example.com", productAgePassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotEmpty(t, login.RefreshToken)

	// The operator now sets a teen minimum on the product.
	restricted := productScope(t, teenMinimumJSON, restrictedProduct)
	_, _, _, err = svc.RefreshToken(restricted, login.RefreshToken, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrProductAgeRestricted)
}

// ── Account-creating paths ───────────────────────────────────────────────

// A signup carries its own date of birth, so the gate applies to the session the
// signup would have issued. A CHILD never reaches it (the age gate parks the
// account in pending-parental-consent with no session), which is why the teen
// case is the one that proves the guardrail on this path.
func TestProductAgeGate_PasswordSignup(t *testing.T) {
	t.Run("teen_refused_by_adult_minimum", func(t *testing.T) {
		svc, _, _ := newProductAgeSvc(t)
		ctx := productScope(t, adultMinimumJSON, restrictedProduct)
		_, err := svc.PasswordSignup(ctx, "teen@example.com", productAgePassword, "Teen", "", dobAgeMs(15), "")
		require.ErrorIs(t, err, ErrProductAgeRestricted)
	})

	t.Run("teen_admitted_by_teen_minimum", func(t *testing.T) {
		svc, _, _ := newProductAgeSvc(t)
		ctx := productScope(t, teenMinimumJSON, restrictedProduct)
		res, err := svc.PasswordSignup(ctx, "teen@example.com", productAgePassword, "Teen", "", dobAgeMs(15), "")
		require.NoError(t, err)
		assert.NotEmpty(t, res.AccessToken)
	})

	t.Run("child_parked_for_consent_before_the_gate", func(t *testing.T) {
		svc, _, _ := newProductAgeSvc(t)
		ctx := productScope(t, adultMinimumJSON, restrictedProduct)
		res, err := svc.PasswordSignup(ctx, "kid@example.com", productAgePassword, "Kid", "", dobAgeMs(8), "")
		require.NoError(t, err)
		assert.Empty(t, res.AccessToken, "a child signup issues no session to gate")
		assert.Equal(t, StatusPendingParentalConsent, res.User.Status)
	})
}

// A passkey signup collects no date of birth, so the account it creates is
// always the unspecified band — which passes by design rather than by accident.
func TestProductAgeGate_PasskeySignupHasNoBandAndPasses(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	enableAgeGate(t, svc, false)
	ctx := productScope(t, adultMinimumJSON, restrictedProduct)

	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))
	res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t),
		pkVectorEmail, otp, "Key", "1.2.3.4", "agent")
	require.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
}

// ── Native OAuth ─────────────────────────────────────────────────────────

// Native mobile login is the one path that resolves its OWN project scope (from
// the product→project map) instead of inheriting the request's, so it would
// silently drop the guardrail if the policy did not travel with the resolved
// project. It is also the path the mobile apps actually use.
func TestProductAgeGate_NativeOAuthLogin(t *testing.T) {
	for _, tc := range []struct {
		name        string
		dobMs       int64
		wantRefused bool
	}{
		{"child_refused", dobAgeMs(8), true},
		{"teen_admitted", dobAgeMs(15), false},
		{"no_dob_admitted", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			userID, err := repo.CreateUser(context.Background(), &User{Email: "native@example.com", Name: "Native"})
			require.NoError(t, err)
			repo.mu.Lock()
			repo.users[userID].DateOfBirthMs = tc.dobMs
			repo.mu.Unlock()

			proj := nativeProjWithAuds("proj-tortoise", "scope-tortoise")
			proj.Products = ProjectProductsConfig{"tortoise": {MinimumAgeBand: MinimumAgeBandTeen}}
			projects := &fakeNativeProjects{active: map[string]*AdminProject{"proj-tortoise": proj}}

			signer := newNativeTokenSigner(t)
			svc := newNativeTestAuthService(t, repo, signer, projects, nil)
			enableAgeGate(t, svc, false)

			ctx := WithProduct(context.Background(), "tortoise")
			tok := signer.googleToken(t, "g-sub-native", "native@example.com", nativeGoogleAud)
			_, err = svc.NativeOAuthLogin(ctx, NativeOAuthLoginParams{
				Provider: "google", IDToken: tok, Product: "tortoise",
			})
			if tc.wantRefused {
				require.ErrorIs(t, err, ErrProductAgeRestricted)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ── Deployment-wide age-gating off ───────────────────────────────────────

// With GATEWAY_AGEGATE_ENABLED off no account has a derived band at all, so the
// product guardrail is inert. It is a real deployment state and must not deny.
func TestProductAgeGate_AgeGatingDisabled_AdmitsEveryone(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	seedUserAged(t, repo, "child@example.com", dobAgeMs(8))

	ctx := productScope(t, adultMinimumJSON, restrictedProduct)
	res, err := svc.PasswordLogin(ctx, "child@example.com", productAgePassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
}

// ── Test fixtures ────────────────────────────────────────────────────────

// productAgeRecoveryCode is the TOTP recovery code the totp_verify path
// redeems; a recovery code proves the second factor without a wall-clock TOTP.
const productAgeRecoveryCode = "ABCDEFGHJK"

// seedTotpChallenge gives userID a verified TOTP credential, an unused recovery
// code, and a pending login challenge, and returns the challenge id — the state
// VerifyTotp needs to complete a second-factor login.
func seedTotpChallenge(t *testing.T, repo *fakeRepo, userID string) string {
	t.Helper()
	encrypted, err := secretcrypto.Encrypt("JBSWY3DPEHPK3PXP", testTotpKey())
	require.NoError(t, err)

	challengeID := "product-age-challenge"
	repo.mu.Lock()
	defer repo.mu.Unlock()
	repo.users[userID].TotpRequired = true
	credID := nextNodeID()
	repo.totpCreds[credID] = &TotpCredRecord{
		NodeID: credID, UserID: userID, SecretEncrypted: encrypted, Verified: true,
	}
	rcID := nextNodeID()
	repo.recoveryCodes[rcID] = &RecoveryCodeRecord{
		NodeID:   rcID,
		UserID:   userID,
		CodeHash: totp.HashRecoveryCode(productAgeRecoveryCode, testTotpRecoveryPepper()),
	}
	lcID := nextNodeID()
	repo.loginChallenges[lcID] = &LoginChallengeRecord{
		NodeID:      lcID,
		ChallengeID: challengeID,
		UserID:      userID,
		ExpiresAt:   time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt:   time.Now().UnixMilli(),
	}
	return challengeID
}

// scopeFromJSON builds the project scope a config_json blob resolves to,
// without a product — the "no X-Product and no configured default" case.
func scopeFromJSON(t *testing.T, configJSON string) *ProjectScope {
	t.Helper()
	cfg, err := ParseProjectConfig(configJSON)
	require.NoError(t, err)
	return &ProjectScope{ProjectID: "project-a", Access: cfg.Access, Products: cfg.Products}
}

// An anonymous account structurally never resolves an age band, so the
// unknown-band pass-through — an identified-account concession justified by
// "children carry a DOB by construction" — must not extend to it. Otherwise
// one unauthenticated SignInAnonymously satisfies every minimum_age_band,
// including adult.
func TestEnforceProductAgeGate_AnonymousFailsClosed(t *testing.T) {
	t.Parallel()
	svc, _, _ := newProductAgeSvc(t)
	anon := &User{ID: "anon-1", IsAnonymous: true}

	// A product with a configured minimum denies an anonymous session.
	err := svc.enforceProductAgeGate(productScope(t, adultMinimumJSON, restrictedProduct), anon)
	require.ErrorIs(t, err, ErrProductAgeRestricted)

	// A product with NO minimum stays open to anonymous sessions — the
	// anti-scraping use case this feature exists for.
	require.NoError(t, svc.enforceProductAgeGate(productScope(t, adultMinimumJSON, "unrestricted-product"), anon))

	// An identified account with the same unknown band still passes: the
	// concession is for accounts that COULD have a DOB on file.
	identified := &User{ID: "u-1", Email: "adult@example.com"}
	require.NoError(t, svc.enforceProductAgeGate(productScope(t, adultMinimumJSON, restrictedProduct), identified))
}
