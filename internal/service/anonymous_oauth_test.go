package service

import (
	"context"
	"errors"
	"testing"
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
func TestAnonymousAccount_CannotAttachCredentialsOutsideUpgrade(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := anonCtx(true, AccessModeOpen)

	res, err := svc.SignInAnonymously(ctx, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}

	_, err = svc.LinkIdentity(ctx, res.User.ID, fakeOAuthCode(testOAuthEmail, "Fed", "", testOAuthProvider), testOAuthProvider, testOAuthRedirect, "", "", "")
	if !errors.Is(err, ErrAnonymousMustUpgrade) {
		t.Fatalf("LinkIdentity on an anonymous account = %v, want ErrAnonymousMustUpgrade", err)
	}

	after, _ := repo.GetUser(ctx, res.User.ID)
	if after == nil || !after.IsAnonymous {
		t.Fatal("the account changed state despite the refusal")
	}
	ids, _ := repo.ListOAuthIdentitiesForUser(context.Background(), res.User.ID)
	if len(ids) != 0 {
		t.Fatalf("a refused link persisted %d identities", len(ids))
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
