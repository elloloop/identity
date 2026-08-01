package service

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/config"
)

// The fake exchanger derives the provider subject from the email in the
// code string; see fakeOAuthCode.
const (
	testOAuthProvider = "google"
	testOAuthRedirect = "https://app/cb"
	testOAuthEmail    = "federated@example.com"
)

func oauthCred() AnonymousOAuthCredential {
	return AnonymousOAuthCredential{
		Provider:    testOAuthProvider,
		Code:        fakeOAuthCode(testOAuthEmail, "Fed Erated", "", testOAuthProvider),
		RedirectURI: testOAuthRedirect,
	}
}

// The OAuth upgrade is one of two credential paths on a new public RPC and
// holds the subtlest decision in the feature — it grants email_verified for
// free when it adopts a provider address. It shipped with zero coverage;
// these are the branches that matter.

func TestUpgradeAnonymousWithOAuth_AdoptsAProviderVerifiedAddress(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	anonID := res.User.ID

	up, err := svc.UpgradeAnonymousWithOAuth(ctx, anonID, oauthCred())
	if err != nil {
		t.Fatalf("UpgradeAnonymousWithOAuth: %v", err)
	}
	if up.User.ID != anonID {
		t.Fatalf("upgrade changed the id: %q -> %q", anonID, up.User.ID)
	}
	if up.User.IsAnonymous {
		t.Error("is_anonymous survived the OAuth upgrade")
	}
	// A federated address is provider-verified, unlike a typed one.
	if !up.User.EmailVerified {
		t.Error("a provider-verified address must be marked verified")
	}
	if up.User.Email == "" {
		t.Error("a permanent account must carry an address")
	}
	if claims := decodeAccessTokenClaims(t, svc, up.AccessToken); claims.Anonymous {
		t.Error("the reissued token still claims anonymity")
	}
}

func TestUpgradeAnonymousWithOAuth_RefusesANonAnonymousCallerBeforeMutating(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	permanent, err := repo.CreateUser(ctx, &User{Email: "already@example.com"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err = svc.UpgradeAnonymousWithOAuth(ctx, permanent, oauthCred())
	if !errors.Is(err, ErrNotAnonymous) {
		t.Fatalf("err = %v, want ErrNotAnonymous", err)
	}
	// The refusal must land BEFORE the provider link is persisted, or a
	// rejected upgrade permanently mutates the account.
	ids, err := repo.ListOAuthIdentitiesForUser(ctx, permanent)
	if err != nil {
		t.Fatalf("ListOAuthIdentities: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("a rejected upgrade linked %d provider identities", len(ids))
	}
}

// The access mode gates the upgrade with SIGNUP semantics: it is what
// provisions an identified account in the project's namespace. Without this
// an unauthenticated caller chains SignInAnonymously into a permanent,
// indefinitely-refreshable account on an invite-only project.
func TestUpgradeAnonymousWithOAuth_GatedByAccessMode(t *testing.T) {
	for _, mode := range []string{AccessModeInvite, AccessModeClosed} {
		t.Run(mode, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			ctx := anonCtx(true, mode)

			res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
			if err != nil {
				t.Fatalf("SignInAnonymously: %v", err)
			}
			if _, err := svc.UpgradeAnonymousWithOAuth(ctx, res.User.ID, oauthCred()); err == nil {
				t.Fatalf("mode %q admitted an upgrade — invite-only projects are bypassable", mode)
			}
			after, _ := repo.GetUser(ctx, res.User.ID)
			if after == nil || !after.IsAnonymous {
				t.Error("a denied upgrade must leave the account anonymous and intact")
			}
		})
	}
}

func TestUpgradeAnonymousWithPassword_GatedByAccessMode(t *testing.T) {
	for _, mode := range []string{AccessModeInvite, AccessModeClosed} {
		t.Run(mode, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			ctx := anonCtx(true, mode)

			res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
			if err != nil {
				t.Fatalf("SignInAnonymously: %v", err)
			}
			if _, err := svc.UpgradeAnonymousWithPassword(ctx, res.User.ID, AnonymousPasswordCredential{
				Email: "new@example.com", Password: "Str0ng-Passw0rd!x",
			}); err == nil {
				t.Fatalf("mode %q admitted a password upgrade", mode)
			}
			after, _ := repo.GetUser(ctx, res.User.ID)
			if after == nil || !after.IsAnonymous {
				t.Error("a denied upgrade must leave the account anonymous")
			}
		})
	}
}

// An anonymous account must not gain a permanent credential through any door
// but the upgrade RPC: the retention sweep keys on is_anonymous, so a
// credential attached elsewhere leaves an account that can log in AND gets
// hard-deleted after the retention window.
// TestAnonymousAccount_CannotAttachCredentialsOutsideUpgrade covers EVERY
// door onto the invariant, not just the one that was easiest to drive.
//
// is_anonymous means "holds no credential", and the retention sweep keys on
// it — so a credential attached anywhere that leaves the flag set produces
// an account that can log in AND gets hard-deleted with its sessions after
// the window. Each guard is the only thing holding that, and the failure is
// silent, so each is asserted here to refuse AND to leave the account
// untouched. Asserting the error alone would pass even if the write landed.
func TestAnonymousAccount_CannotAttachCredentialsOutsideUpgrade(t *testing.T) {
	doors := []struct {
		name string
		call func(svc *AuthService, ctx context.Context, userID string) error
	}{
		{"LinkIdentity", func(svc *AuthService, ctx context.Context, id string) error {
			_, err := svc.LinkIdentity(ctx, id,
				fakeOAuthCode(testOAuthEmail, "Fed", "", testOAuthProvider),
				testOAuthProvider, testOAuthRedirect, "", "", "")
			return err
		}},
		{"BeginPasskeyRegistration", func(svc *AuthService, ctx context.Context, id string) error {
			_, _, err := svc.BeginPasskeyRegistration(ctx, id, "device")
			return err
		}},
		{"CompletePasskeyRegistration", func(svc *AuthService, ctx context.Context, id string) error {
			_, err := svc.CompletePasskeyRegistration(ctx, id, "challenge", `{"id":"x"}`, "device")
			return err
		}},
		{"RequestPhoneVerification", func(svc *AuthService, ctx context.Context, id string) error {
			return svc.RequestPhoneVerification(ctx, id, "+14155550123")
		}},
		{"VerifyPhoneCode", func(svc *AuthService, ctx context.Context, id string) error {
			_, err := svc.VerifyPhoneCode(ctx, id, "+14155550123", "123456")
			return err
		}},
	}

	for _, d := range doors {
		t.Run(d.name, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			svc.cfg.SMSEnabled = true // so the phone doors reach the guard
			ctx := anonCtx(true, AccessModeOpen)

			res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
			if err != nil {
				t.Fatalf("SignInAnonymously: %v", err)
			}
			id := res.User.ID

			if err := d.call(svc, ctx, id); !errors.Is(err, ErrAnonymousMustUpgrade) {
				t.Fatalf("%s on an anonymous account = %v, want ErrAnonymousMustUpgrade", d.name, err)
			}

			after, _ := repo.GetUser(ctx, id)
			if after == nil || !after.IsAnonymous {
				t.Fatalf("%s changed the account despite refusing: %#v", d.name, after)
			}
			ids, _ := repo.ListOAuthIdentitiesForUser(ctx, id)
			if len(ids) != 0 {
				t.Errorf("%s persisted %d provider identities", d.name, len(ids))
			}
		})
	}
}

// TestUpgradeAnonymousWithPassword_HonoursVerifiedEmailGate pins the control
// that makes the upgrade no more powerful than signup.
//
// GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL defaults TRUE. Without it honoured
// here, an unauthenticated caller could chain SignInAnonymously into a LIVE
// session whose JWT asserts an address they merely typed — someone else's —
// with no verification mail and so no signal to its owner. Via PasswordSignup
// the same caller receives zero tokens.
func TestUpgradeAnonymousWithPassword_HonoursVerifiedEmailGate(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AuthRequireVerifiedEmail = true // the production default
	ctx := anonCtx(true, AccessModeOpen)

	signIn, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	anonID := signIn.User.ID

	up, err := svc.UpgradeAnonymousWithPassword(ctx, anonID, AnonymousPasswordCredential{
		Email: "victim@corp.example.com", Password: "Str0ng-Passw0rd!x",
	})
	if err != nil {
		t.Fatalf("UpgradeAnonymousWithPassword: %v", err)
	}

	// Promoted — but with NO session, mirroring PasswordSignup.
	if up.AccessToken != "" || up.RefreshToken != "" {
		t.Fatal("the upgrade issued a live session on an unverified, caller-supplied address")
	}
	if up.User == nil || up.User.IsAnonymous {
		t.Fatal("the account should still have been promoted")
	}
	if up.User.EmailVerified {
		t.Error("a typed address must not be marked verified")
	}

	// The prior anonymous session must not survive as a back door to the
	// session the gate just withheld.
	if _, _, _, err := svc.RefreshToken(ctx, signIn.RefreshToken, "1.2.3.4", "ua"); err == nil {
		t.Error("the pre-upgrade refresh token still works — the withheld session is reachable anyway")
	}
}

// With the gate off, the upgrade behaves as before: promoted and signed in.
func TestUpgradeAnonymousWithPassword_IssuesASessionWhenVerificationIsNotRequired(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.AuthRequireVerifiedEmail = false
	ctx := anonCtx(true, AccessModeOpen)

	signIn, _ := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	up, err := svc.UpgradeAnonymousWithPassword(ctx, signIn.User.ID, AnonymousPasswordCredential{
		Email: "ok@example.com", Password: "Str0ng-Passw0rd!x",
	})
	if err != nil {
		t.Fatalf("UpgradeAnonymousWithPassword: %v", err)
	}
	if up.AccessToken == "" || up.RefreshToken == "" {
		t.Fatal("no session issued with the verification gate off")
	}
}

// TestUpgradeAnonymousWithOAuth_RetryAfterAFailedPromotion pins the
// idempotence that makes the two-write path recoverable.
//
// The OAuth arm writes the provider identity and then promotes the account,
// with no transaction. If the promotion fails, the identity must not be
// stranded on a still-anonymous account: that account stays inside the
// retention sweep's reach and is hard-deleted with the credential, and
// because the identity is claimed, no account on the deployment could ever
// link it again.
func TestUpgradeAnonymousWithOAuth_RetryAfterAFailedPromotion(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	signIn, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	anonID := signIn.User.ID

	// Fail the promotion write.
	repo.updateUserErr = errors.New("connection reset by peer")
	if _, err := svc.UpgradeAnonymousWithOAuth(ctx, anonID, oauthCred()); err == nil {
		t.Fatal("upgrade reported success despite a failed promotion")
	}

	// The compensation must have removed the identity, leaving the account
	// exactly as it was.
	ids, err := repo.ListOAuthIdentitiesForUser(ctx, anonID)
	if err != nil {
		t.Fatalf("ListOAuthIdentitiesForUser: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("a failed promotion stranded %d provider identities", len(ids))
	}

	// And the retry succeeds rather than returning ALREADY_EXISTS against
	// the caller's own identity.
	repo.updateUserErr = nil
	up, err := svc.UpgradeAnonymousWithOAuth(ctx, anonID, oauthCred())
	if err != nil {
		t.Fatalf("retry after a failed promotion: %v", err)
	}
	if up.User.ID != anonID || up.User.IsAnonymous {
		t.Fatalf("retry produced %#v", up.User)
	}
}

// The upgrade's guard rails, each of which refuses before touching the
// account. These are cheap to get wrong and expensive to notice: a missing
// refusal here is an account promoted into a state the deployment's own
// switches say is impossible.
func TestUpgradeAnonymousWithPassword_Refusals(t *testing.T) {
	newAnon := func(t *testing.T) (*AuthService, *fakeRepo, context.Context, string) {
		t.Helper()
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		ctx := anonCtx(true, AccessModeOpen)
		res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
		if err != nil {
			t.Fatalf("SignInAnonymously: %v", err)
		}
		return svc, repo, ctx, res.User.ID
	}

	t.Run("local auth disabled", func(t *testing.T) {
		svc, _, ctx, id := newAnon(t)
		svc.cfg.AuthAllowLocal = false
		if _, err := svc.UpgradeAnonymousWithPassword(ctx, id, AnonymousPasswordCredential{
			Email: "a@example.com", Password: "Str0ng-Passw0rd!x",
		}); !errors.Is(err, ErrLocalAuthDisabled) {
			t.Fatalf("err = %v, want ErrLocalAuthDisabled", err)
		}
	})

	t.Run("password signup disabled", func(t *testing.T) {
		svc, _, ctx, id := newAnon(t)
		svc.cfg.PasswordSignupEnabled = false
		if _, err := svc.UpgradeAnonymousWithPassword(ctx, id, AnonymousPasswordCredential{
			Email: "b@example.com", Password: "Str0ng-Passw0rd!x",
		}); !errors.Is(err, ErrSignupDisabled) {
			t.Fatalf("err = %v, want ErrSignupDisabled", err)
		}
	})

	t.Run("malformed address", func(t *testing.T) {
		svc, _, ctx, id := newAnon(t)
		if _, err := svc.UpgradeAnonymousWithPassword(ctx, id, AnonymousPasswordCredential{
			Email: "not-an-address", Password: "Str0ng-Passw0rd!x",
		}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("empty password", func(t *testing.T) {
		svc, _, ctx, id := newAnon(t)
		if _, err := svc.UpgradeAnonymousWithPassword(ctx, id, AnonymousPasswordCredential{
			Email: "c@example.com",
		}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("a repo failure is surfaced, not swallowed", func(t *testing.T) {
		svc, repo, ctx, id := newAnon(t)
		repo.findUserByEmailErr = errors.New("connection reset")
		if _, err := svc.UpgradeAnonymousWithPassword(ctx, id, AnonymousPasswordCredential{
			Email: "d@example.com", Password: "Str0ng-Passw0rd!x",
		}); err == nil {
			t.Fatal("a lookup failure was swallowed")
		}
		after, _ := repo.GetUser(ctx, id)
		if after == nil || !after.IsAnonymous {
			t.Error("a failed upgrade must leave the account anonymous")
		}
	})
}

// The OAuth arm refuses a provider that returns no email: a permanent
// account must have an address, or it occupies the empty-email slot the
// partial index reserves for anonymous users and cannot be recovered.
func TestUpgradeAnonymousWithOAuth_RefusesAnEmailessProvider(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	cred := oauthCred()
	cred.Code = fakeOAuthCode("", "No Email", "", testOAuthProvider)

	if _, err := svc.UpgradeAnonymousWithOAuth(ctx, res.User.ID, cred); err == nil {
		t.Fatal("upgrade accepted a provider identity with no email")
	}
	after, _ := repo.GetUser(ctx, res.User.ID)
	if after == nil || !after.IsAnonymous {
		t.Error("the account must stay anonymous")
	}
	ids, _ := repo.ListOAuthIdentitiesForUser(ctx, res.User.ID)
	if len(ids) != 0 {
		t.Errorf("a refused upgrade persisted %d identities", len(ids))
	}
}

// A caller that does not exist, and one already promoted, are both refused
// before the exchange.
func TestUpgradeAnonymousWithOAuth_UnknownCaller(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	if _, err := svc.UpgradeAnonymousWithOAuth(ctx, "no-such-user", oauthCred()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// A failed activity stamp must not fail the refresh: losing one stamp only
// makes the account look idle until its next refresh, whereas failing the
// refresh would strand a session whose token is the account's only
// credential.
func TestRefreshToken_AnonymousActivityStampFailureIsNotFatal(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	repo.updateUserErr = errors.New("connection reset")

	if _, access, refresh, err := svc.RefreshToken(ctx, res.RefreshToken, "1.2.3.4", "ua"); err != nil {
		t.Fatalf("a failed activity stamp broke the refresh: %v", err)
	} else if access == "" || refresh == "" {
		t.Fatal("refresh returned no tokens")
	}
}

// The credential-attach guard fails CLOSED on a lookup error: guessing
// "probably not anonymous" is the direction that loses data.
func TestRefuseAnonymousCredentialAttach_FailsClosedOnLookupError(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	repo.getUserErr = errors.New("connection reset")

	if err := svc.refuseAnonymousCredentialAttach(context.Background(), "some-user"); err == nil {
		t.Fatal("a lookup failure admitted the credential attach")
	}
}

// The provider identity must be unclaimed by ANOTHER account; Firebase's
// credential-already-in-use, deliberately not a merge.
func TestUpgradeAnonymousWithOAuth_RefusesAnIdentityOwnedByAnother(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	// Another account already holds this provider identity.
	other, err := repo.CreateUser(ctx, &User{Email: "other@example.com"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: other, Provider: testOAuthProvider,
		ProviderUserID: "sub-" + testOAuthEmail, CreatedAt: 1,
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	res, _ := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	// A different address, so the email pre-check passes and the identity
	// check is what refuses.
	cred := oauthCred()
	if _, err := svc.UpgradeAnonymousWithOAuth(ctx, res.User.ID, cred); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
	after, _ := repo.GetUser(ctx, res.User.ID)
	if after == nil || !after.IsAnonymous {
		t.Error("a refused upgrade must leave the account anonymous")
	}
}

// TestUpgradeAnonymousWithPassword_RevokesTheAccessSessionToo pins the half
// of the verified-email gate that the withheld-tokens assertion cannot see.
//
// Deleting refresh tokens does not end a session: under
// GATEWAY_REVOCATION_MODE=session the access token's lifetime is uncapped and
// it is revocable only through its Session row. Without revoking that, the
// caller keeps a working token against a subject that now bears the address
// they just claimed — exactly the session the gate withholds.
func TestUpgradeAnonymousWithPassword_RevokesTheAccessSessionToo(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.RevocationMode = config.RevocationModeSession
	svc.cfg.AuthRequireVerifiedEmail = true
	ctx := anonCtx(true, AccessModeOpen)

	signIn, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	claims := decodeAccessTokenClaims(t, svc, signIn.AccessToken)
	if claims.SID == "" {
		t.Fatal("revocation mode session should have minted a session id")
	}

	if _, err := svc.UpgradeAnonymousWithPassword(ctx, signIn.User.ID, AnonymousPasswordCredential{
		Email: "claimed@example.com", Password: "Str0ng-Passw0rd!x",
	}); err != nil {
		t.Fatalf("UpgradeAnonymousWithPassword: %v", err)
	}

	// The pre-upgrade access token must no longer be usable.
	sess, err := repo.GetSessionBySid(ctx, claims.SID)
	if err != nil {
		t.Fatalf("GetSessionBySid: %v", err)
	}
	if sess != nil && sess.RevokedAtMs == 0 {
		t.Fatal("the pre-upgrade access session is still active — the withheld session remains reachable")
	}
}

// TestUpgradeAnonymousWithPassword_DoesNotLeakAddressExistence pins the
// ordering that closes an enumeration oracle.
//
// The address probe answers a question about OTHER accounts, and its
// ALREADY_EXISTS was distinguishable from the not-anonymous refusal — so
// checking it first let ANY authenticated caller walk the project's
// registered addresses, straight around the decoy-success anti-enumeration
// work PasswordSignup invests in.
func TestUpgradeAnonymousWithPassword_DoesNotLeakAddressExistence(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	if _, err := repo.CreateUser(ctx, &User{Email: "registered@example.com"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A permanent (non-anonymous) caller — the enumerating party.
	caller, err := repo.CreateUser(ctx, &User{Email: "caller@example.com"})
	if err != nil {
		t.Fatalf("seed caller: %v", err)
	}

	_, errTaken := svc.UpgradeAnonymousWithPassword(ctx, caller, AnonymousPasswordCredential{
		Email: "registered@example.com", Password: "Str0ng-Passw0rd!x",
	})
	_, errFree := svc.UpgradeAnonymousWithPassword(ctx, caller, AnonymousPasswordCredential{
		Email: "definitely-unused@example.com", Password: "Str0ng-Passw0rd!x",
	})

	// Both must be the SAME refusal — the caller is not anonymous, and that
	// is all it may learn. A differing error is the oracle.
	if !errors.Is(errTaken, ErrNotAnonymous) || !errors.Is(errFree, ErrNotAnonymous) {
		t.Fatalf("taken=%v free=%v; both should be ErrNotAnonymous", errTaken, errFree)
	}
	if errTaken.Error() != errFree.Error() {
		t.Fatalf("responses differ by address existence:\n taken: %v\n free:  %v", errTaken, errFree)
	}
}

// Anonymous accounts must be invisible to the user-listing surface: they
// have no email, and every consumer presents users by one. SCIM makes
// userName REQUIRED and unique (RFC 7643 §4.1.1), so exporting them yields
// resources with an empty userName and inflates totalResults.
func TestListUsers_ExcludesAnonymousByDefault(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	if _, err := repo.CreateUser(ctx, &User{Email: "real@example.com"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua"); err != nil {
			t.Fatalf("SignInAnonymously: %v", err)
		}
	}

	listed, err := repo.ListUsers(ctx, UserListFilter{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, u := range listed {
		if u.IsAnonymous {
			t.Fatalf("an anonymous account leaked into the default listing: %#v", u)
		}
	}
	if len(listed) != 1 {
		t.Fatalf("listed %d users, want 1 (the addressed one)", len(listed))
	}

	n, err := repo.CountUsers(ctx, UserListFilter{})
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	// The count must agree with the rows, or a paginated consumer walks off
	// the end of a page that never arrives.
	if n != len(listed) {
		t.Fatalf("CountUsers = %d but ListUsers returned %d", n, len(listed))
	}

	// Opt-in still sees them, for surfaces that genuinely want the whole pool.
	all, err := repo.ListUsers(ctx, UserListFilter{IncludeAnonymous: true})
	if err != nil {
		t.Fatalf("ListUsers(IncludeAnonymous): %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("IncludeAnonymous listed %d, want 4", len(all))
	}
}
