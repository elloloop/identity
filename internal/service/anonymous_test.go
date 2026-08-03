package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/jwt"
)

// decodeAccessTokenClaims verifies and decodes an access token minted by
// svc, so assertions read the claims a real verifier would see rather than
// a hand-parsed payload.
func decodeAccessTokenClaims(t *testing.T, svc *AuthService, token string) *jwt.Claims {
	t.Helper()
	claims, err := jwt.VerifyAccessToken(token, svc.signer, "", "", false)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	return claims
}

// anonCtx returns a request context scoped to a project with the given
// anonymous switch and access mode. The two are set independently on
// purpose — their independence is what most of this file tests.
func anonCtx(enabled bool, mode string) context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "proj-anon",
		Access:    ProjectAccessConfig{Mode: mode},
		Anonymous: ProjectAnonymousConfig{Enabled: enabled},
	})
}

func TestSignInAnonymously_DisabledByDefault(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// An open project with no anonymous block must still refuse: the
	// capability is opt-in, never implied by the access mode.
	_, err := svc.SignInAnonymously(anonCtx(false, AccessModeOpen), "1.2.3.4", "ua")
	if !errors.Is(err, ErrAnonymousDisabled) {
		t.Fatalf("disabled project err = %v, want ErrAnonymousDisabled", err)
	}
}

func TestSignInAnonymously_NoProjectScopeIsDenied(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// No scope means no project whose policy could have enabled this. The
	// access guard passes through on a nil scope ("no gate to apply"); this
	// one must NOT ("nothing turned it on").
	_, err := svc.SignInAnonymously(context.Background(), "1.2.3.4", "ua")
	if !errors.Is(err, ErrAnonymousDisabled) {
		t.Fatalf("unscoped err = %v, want ErrAnonymousDisabled", err)
	}
}

// TestSignInAnonymously_IndependentOfAccessMode is the load-bearing test for
// this feature's central design decision: anonymous sign-in is orthogonal to
// the access mode, Firebase-exact. `access.mode` governs which
// EMAIL-IDENTIFIED humans may sign up and log in; an anonymous session is a
// different question, so even mode=closed — which admits no new identified
// users at all — must still hand out anonymous sessions when the project
// turns them on.
//
// Getting this wrong is silent: an anonymous user has no email, so any code
// that routes them through the access guard judges them as the empty address
// and denies under every mode except `open`.
func TestSignInAnonymously_IndependentOfAccessMode(t *testing.T) {
	for _, mode := range []string{AccessModeOpen, AccessModeAllowlist, AccessModeInvite, AccessModeClosed, ""} {
		label := mode
		if label == "" {
			label = "unset"
		}
		t.Run(label, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)

			res, err := svc.SignInAnonymously(anonCtx(true, mode), "1.2.3.4", "ua")
			if err != nil {
				t.Fatalf("access mode %q blocked anonymous sign-in: %v — the two switches are independent", label, err)
			}
			if res.User == nil || !res.User.IsAnonymous {
				t.Fatalf("user = %#v, want IsAnonymous", res.User)
			}
			if res.AccessToken == "" || res.RefreshToken == "" {
				t.Error("anonymous sign-in must return a usable token pair")
			}
		})
	}
}

func TestSignInAnonymously_CreatesCredentiallessUser(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeClosed)

	res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	u := res.User

	if u.Email != "" {
		t.Errorf("Email = %q, want empty — an anonymous account has no address", u.Email)
	}
	if u.PasswordHash != "" {
		t.Error("anonymous account must carry no password hash")
	}
	if u.Status != "active" {
		t.Errorf("Status = %q, want active", u.Status)
	}
	// The retention sweep keys on this. Zero would make every new account
	// instantly older than any cutoff and reap it on the next tick.
	if u.AnonymousLastSeenMs == 0 {
		t.Error("AnonymousLastSeenMs is zero — a new anonymous user would be swept immediately")
	}

	// The address must not resolve the account: FindUserByEmail("") is how a
	// login for a missing address would land here.
	got, err := repo.FindUserByEmail(ctx, "")
	if err != nil || got != nil {
		t.Fatalf("FindUserByEmail(\"\") = (%#v, %v), want (nil, nil)", got, err)
	}
}

func TestSignInAnonymously_EachCallMintsADistinctUser(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
		if err != nil {
			// The per-project email unique index must be PARTIAL; a total one
			// makes the second empty-email insert a duplicate-key error.
			t.Fatalf("anonymous sign-in #%d failed: %v", i+1, err)
		}
		if seen[res.User.ID] {
			t.Fatalf("sign-in #%d reused user id %q", i+1, res.User.ID)
		}
		seen[res.User.ID] = true
	}
}

func TestSignInAnonymously_TokenCarriesAnonymousClaim(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	res, err := svc.SignInAnonymously(anonCtx(true, AccessModeOpen), "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	claims := decodeAccessTokenClaims(t, svc, res.AccessToken)
	if !claims.Anonymous {
		t.Error("access token is missing the anonymous claim — downstream services would treat this as a verified human")
	}
	if claims.Sub == "" {
		t.Error("anonymous token must still carry a sub: the account is real and stable")
	}
	if claims.Email != "" {
		t.Errorf("anonymous token carries email %q", claims.Email)
	}
}

func TestUpgradeAnonymousUser_PreservesIDAndClearsFlag(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	originalID := res.User.ID

	up, err := svc.UpgradeAnonymousWithPassword(ctx, originalID, AnonymousPasswordCredential{
		Email:    "claimed@example.com",
		Password: "Str0ng-Passw0rd!x",
	})
	if err != nil {
		t.Fatalf("UpgradeAnonymousWithPassword: %v", err)
	}

	// The whole point: everything the client wrote against this id stays
	// attached to the same subject.
	if up.User.ID != originalID {
		t.Fatalf("upgrade changed the user id: %q -> %q", originalID, up.User.ID)
	}
	if up.User.IsAnonymous {
		t.Error("is_anonymous survived the upgrade — the account stays in the retention sweep's reach")
	}
	if up.User.Email != "claimed@example.com" {
		t.Errorf("Email = %q after upgrade", up.User.Email)
	}
	// A typed address is unproven; marking it verified would hand out a
	// verified identity for free.
	if up.User.EmailVerified {
		t.Error("a self-asserted email must not be marked verified by the upgrade")
	}

	// The reissued token must no longer claim anonymity.
	claims := decodeAccessTokenClaims(t, svc, up.AccessToken)
	if claims.Anonymous {
		t.Error("reissued token still carries anonymous=true")
	}
	if claims.Sub != originalID {
		t.Errorf("reissued token sub = %q, want the preserved id %q", claims.Sub, originalID)
	}
}

func TestUpgradeAnonymousUser_RefusesASecondUpgrade(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	res, _ := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if _, err := svc.UpgradeAnonymousWithPassword(ctx, res.User.ID, AnonymousPasswordCredential{
		Email: "first@example.com", Password: "Str0ng-Passw0rd!x",
	}); err != nil {
		t.Fatalf("first upgrade: %v", err)
	}

	// A second upgrade would silently rebind an identified account to a
	// different credential.
	_, err := svc.UpgradeAnonymousWithPassword(ctx, res.User.ID, AnonymousPasswordCredential{
		Email: "second@example.com", Password: "Str0ng-Passw0rd!x",
	})
	if !errors.Is(err, ErrNotAnonymous) {
		t.Fatalf("second upgrade err = %v, want ErrNotAnonymous", err)
	}
}

func TestUpgradeAnonymousUser_RejectsAClaimedAddress(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	if _, err := repo.CreateUser(ctx, &User{Email: "taken@example.com"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res, _ := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")

	// Unlike signup, this must NOT return an anti-enumeration decoy: the
	// caller is authenticated as the account being upgraded, and would
	// otherwise believe it holds a permanent account it cannot log into.
	_, err := svc.UpgradeAnonymousWithPassword(ctx, res.User.ID, AnonymousPasswordCredential{
		Email: "taken@example.com", Password: "Str0ng-Passw0rd!x",
	})
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("claimed-address upgrade err = %v, want ErrAlreadyExists", err)
	}

	// The account must be untouched: still anonymous, still usable.
	after, err := repo.GetUser(ctx, res.User.ID)
	if err != nil || after == nil {
		t.Fatalf("GetUser after failed upgrade = (%#v, %v)", after, err)
	}
	if !after.IsAnonymous {
		t.Error("a failed upgrade cleared is_anonymous, stranding the account with no credential")
	}
}

func TestUpgradeAnonymousUser_RejectsAWeakPasswordBeforeTouchingTheAccount(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	res, _ := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	_, err := svc.UpgradeAnonymousWithPassword(ctx, res.User.ID, AnonymousPasswordCredential{
		Email: "weak@example.com", Password: "x",
	})
	if err == nil {
		t.Fatal("a weak password was accepted")
	}
	after, _ := repo.GetUser(ctx, res.User.ID)
	if after == nil || !after.IsAnonymous {
		t.Error("a rejected upgrade must leave the account anonymous and intact")
	}
}

func TestUpgradeAnonymousUser_RejectsAnUnknownOrNonAnonymousCaller(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	if err := svc.UpgradeAnonymousUser(ctx, "", nil); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("empty user id err = %v, want ErrUnauthenticated", err)
	}
	if err := svc.UpgradeAnonymousUser(ctx, "no-such-user", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user err = %v, want ErrNotFound", err)
	}

	id, err := repo.CreateUser(ctx, &User{Email: "permanent@example.com"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.UpgradeAnonymousUser(ctx, id, nil); !errors.Is(err, ErrNotAnonymous) {
		t.Errorf("never-anonymous user err = %v, want ErrNotAnonymous", err)
	}
}

// TestRefreshToken_AnonymousSurvivesAClosedProject covers the cross-cutting
// half of the orthogonality rule. The refresh path re-enforces the access
// mode on every rotation so a de-allowlisted user stops minting tokens — but
// an anonymous user has no email, so running them through that guard judges
// them as the empty address and DENIES under every mode except `open`.
//
// Anonymous sessions would then die at their first refresh on any
// allowlist/invite/closed project, and since a refresh token is the account's
// only credential, unrecoverably.
func TestRefreshToken_AnonymousSurvivesAClosedProject(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeClosed)

	res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}

	user, access, refresh, err := svc.RefreshToken(ctx, res.RefreshToken, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("anonymous refresh on a closed project failed: %v — the session is unrecoverable", err)
	}
	if user.ID != res.User.ID {
		t.Errorf("refresh returned user %q, want %q", user.ID, res.User.ID)
	}
	if access == "" || refresh == "" {
		t.Error("refresh must return a fresh pair")
	}
	if claims := decodeAccessTokenClaims(t, svc, access); !claims.Anonymous {
		t.Error("the refreshed token dropped the anonymous claim")
	}
}

// Turning the feature OFF must stop refreshes: the switch has to be a real
// kill switch, not merely a creation gate.
func TestRefreshToken_AnonymousStopsWhenTheFeatureIsDisabled(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	res, err := svc.SignInAnonymously(anonCtx(true, AccessModeOpen), "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}

	_, _, _, err = svc.RefreshToken(anonCtx(false, AccessModeOpen), res.RefreshToken, "1.2.3.4", "ua")
	if !errors.Is(err, ErrAnonymousRefreshDisabled) {
		t.Fatalf("refresh after disabling err = %v, want ErrAnonymousRefreshDisabled", err)
	}

	// The refusal must NOT have consumed the token. It is the account's only
	// credential, so burning it makes re-enabling the feature useless and
	// leaves the account permanently unreachable — then hard-deleted by the
	// retention sweep. Re-enable and confirm the same token still works.
	user, access, refresh, err := svc.RefreshToken(anonCtx(true, AccessModeOpen), res.RefreshToken, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("the refusal burned the token: re-enabling did not restore the session: %v", err)
	}
	if user.ID != res.User.ID || access == "" || refresh == "" {
		t.Fatalf("recovery returned %#v / empty tokens", user)
	}
}

// A refusal from the product age gate must not consume the token either. The
// gate's anonymous deny arm (see enforceProductAgeGate) is reachable
// mid-session — a product can gain a minimum_age_band between sign-in and the
// next rotation, or the refresh can carry a different X-Product than the
// sign-in did — and a post-consume denial burns the account's only
// credential exactly the way the disabled-feature refusal above would.
func TestRefreshToken_AnonymousAgeGateRefusalDoesNotBurnTheToken(t *testing.T) {
	const anonOpenJSON = `{"access":{"mode":"open"},"anonymous":{"enabled":true}}`
	const anonTeenMinimumJSON = `{"access":{"mode":"open"},"anonymous":{"enabled":true},` +
		`"products":{"hold":{"minimum_age_band":"teen"}}}`

	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	open := productScope(t, anonOpenJSON, restrictedProduct)

	res, err := svc.SignInAnonymously(open, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}

	gated := productScope(t, anonTeenMinimumJSON, restrictedProduct)
	_, _, _, err = svc.RefreshToken(gated, res.RefreshToken, "1.2.3.4", "ua")
	if !errors.Is(err, ErrProductAgeRestricted) {
		t.Fatalf("refresh under a product minimum err = %v, want ErrProductAgeRestricted", err)
	}

	// The refusal must NOT have consumed the token: removing the minimum (or
	// fixing the product header) must restore the session, not find it burned
	// and the next attempt tripping replay detection.
	user, access, refresh, err := svc.RefreshToken(open, res.RefreshToken, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("the refusal burned the token: removing the minimum did not restore the session: %v", err)
	}
	if user.ID != res.User.ID || access == "" || refresh == "" {
		t.Fatalf("recovery returned %#v / empty tokens", user)
	}
}

// A permanent user must keep being judged by the access mode — the exemption
// above is for anonymous accounts only, not a hole in the access guard.
func TestRefreshToken_PermanentUserStillGatedByAccessMode(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	open := anonCtx(true, AccessModeOpen)

	res, _ := svc.SignInAnonymously(open, "1.2.3.4", "ua")
	up, err := svc.UpgradeAnonymousWithPassword(open, res.User.ID, AnonymousPasswordCredential{
		Email: "now-permanent@example.com", Password: "Str0ng-Passw0rd!x",
	})
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}

	_, _, _, err = svc.RefreshToken(anonCtx(true, AccessModeClosed), up.RefreshToken, "1.2.3.4", "ua")
	if err == nil {
		t.Fatal("an upgraded (permanent) user refreshed on a closed project — the access guard was bypassed")
	}
	if errors.Is(err, ErrAnonymousDisabled) {
		t.Fatalf("permanent user hit the anonymous branch: %v", err)
	}
}

// The retention sweep keys on last activity, and refresh is an anonymous
// account's only recurring sign of life. Without this stamp the timestamp
// never advances and every anonymous user dies exactly one retention window
// after creation, however actively it is used.
func TestRefreshToken_AnonymousActivityIsStamped(t *testing.T) {
	repo := newFakeRepo()
	now := int64(1_800_000_000_000)
	svc := newTestAuthServiceWithTime(t, repo, func() time.Time { return time.UnixMilli(now) })
	ctx := anonCtx(true, AccessModeOpen)

	res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	created := res.User.AnonymousLastSeenMs

	now += int64(48 * time.Hour / time.Millisecond)
	if _, _, _, err := svc.RefreshToken(ctx, res.RefreshToken, "1.2.3.4", "ua"); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	after, err := repo.GetUser(ctx, res.User.ID)
	if err != nil || after == nil {
		t.Fatalf("GetUser = (%#v, %v)", after, err)
	}
	if after.AnonymousLastSeenMs <= created {
		t.Fatalf("AnonymousLastSeenMs did not advance on refresh (%d -> %d): an active account would be reaped on schedule",
			created, after.AnonymousLastSeenMs)
	}
}

func TestProjectAnonymousConfig_Validate(t *testing.T) {
	// The block carries a single boolean; both states are valid. There is
	// deliberately no per-project retention override — the sweeper runs
	// against the default-project repo, so one would be config the server
	// silently ignores.
	if err := (ProjectAnonymousConfig{Enabled: true}).validate(); err != nil {
		t.Errorf("enabled config rejected: %v", err)
	}
	if err := (ProjectAnonymousConfig{}).validate(); err != nil {
		t.Errorf("zero config rejected: %v", err)
	}
}

func TestParseProjectConfig_AnonymousBlock(t *testing.T) {
	cfg, err := ParseProjectConfig(`{"anonymous":{"enabled":true}}`)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	if !cfg.Anonymous.Enabled {
		t.Fatalf("anonymous block = %#v", cfg.Anonymous)
	}

	// Absent block leaves the feature off.
	cfg, err = ParseProjectConfig(`{"access":{"mode":"open"}}`)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	if cfg.Anonymous.Enabled {
		t.Error("anonymous defaulted to enabled")
	}
}
