package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/jwt"
)

// newRecoverySignInFixture is a project that keeps recovery emails and lets
// them sign in, with the given access policy.
func newRecoverySignInFixture(t *testing.T, access ProjectAccessConfig) *recoveryEmailFixture {
	t.Helper()
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true, SignIn: true})
	scope := *ProjectScopeFromContext(f.ctx)
	scope.Access = access
	f.ctx = WithProjectScope(context.Background(), &scope)
	return f
}

// signInWith runs the emailed-code sign-in for addr.
func (f *recoveryEmailFixture) signInWith(ctx context.Context, t *testing.T, addr string) (*LoginResult, error) {
	t.Helper()
	if err := f.svc.RequestEmailLoginCode(ctx, addr); err != nil {
		t.Fatalf("RequestEmailLoginCode(%s): %v", addr, err)
	}
	return f.svc.VerifyEmailLoginCode(ctx, addr, f.codeMailedTo(t, strings.ToLower(addr)), "203.0.113.7", "test-agent")
}

func (f *recoveryEmailFixture) userCount() int {
	f.repo.mu.Lock()
	defer f.repo.mu.Unlock()
	return len(f.repo.users)
}

func TestRecoveryEmailSignIn_LandsInTheHoldingAccountAndTellsItsOtherAddresses(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	user.EmailVerified = true
	f.add(t, user, "spare@example.net")
	f.add(t, user, "second@example.net")
	users, sent := f.userCount(), f.mailer.count()

	result, err := f.signInWith(f.ctx, t, "Spare@example.net")
	if err != nil {
		t.Fatalf("sign-in by a recovery email: %v", err)
	}
	if result.User.ID != user.ID || result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatalf("signed in to %q with tokens %t/%t, want the holding account %q",
			result.User.ID, result.AccessToken != "", result.RefreshToken != "", user.ID)
	}
	if f.userCount() != users {
		t.Fatalf("the sign-in made a new account: %d users, want %d", f.userCount(), users)
	}
	const subject = "Your account was signed in to with a recovery email"
	for _, addr := range []string{"owner@example.com", "second@example.net"} {
		got := f.mailedTo(addr)
		if len(got) == 0 || got[len(got)-1].Subject != subject {
			t.Fatalf("%s was not told of the sign-in: %#v", addr, got)
		}
	}
	// The login code, then nothing: the address that signed in needs no notice.
	if f.mailer.count() != sent+3 {
		t.Fatalf("%d messages after the request, want the code and two notices", f.mailer.count()-sent)
	}
}

// sessionAMR is the amr claim of an access token the fixture's service minted.
func (f *recoveryEmailFixture) sessionAMR(t *testing.T, accessToken string) []string {
	t.Helper()
	claims, err := jwt.VerifyAccessToken(accessToken, f.svc.signer, "", "", false)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	return claims.AMR
}

// holdUntil is when the hold on user's recovery settings ends, 0 for none.
func (f *recoveryEmailFixture) holdUntil(t *testing.T, userID string) int64 {
	t.Helper()
	_, until, err := f.svc.ListRecoveryEmails(f.ctx, userID)
	if err != nil {
		t.Fatalf("ListRecoveryEmails: %v", err)
	}
	return until
}

// heldChanges are the changes a session a recovery hold binds may not make,
// each asked for by session.
func (f *recoveryEmailFixture) heldChanges(userID string, session SessionSignIn) map[string]func() error {
	return map[string]func() error{
		"RequestRecoveryEmail": func() error {
			return f.svc.RequestRecoveryEmail(f.ctx, userID, session, "added@example.net")
		},
		"VerifyRecoveryEmail": func() error {
			_, err := f.svc.VerifyRecoveryEmail(f.ctx, userID, session, "added@example.net", "123456")
			return err
		},
		"RemoveRecoveryEmail": func() error {
			_, err := f.svc.RemoveRecoveryEmail(f.ctx, userID, session, "spare@example.net")
			return err
		},
		"RequestPhoneVerification": func() error {
			return f.svc.RequestPhoneVerification(f.ctx, userID, session, "+14155550123")
		},
		"VerifyPhoneCode": func() error {
			_, err := f.svc.VerifyPhoneCode(f.ctx, userID, session, "+14155550123", "123456")
			return err
		},
		"RemovePhone": func() error {
			_, err := f.svc.RemovePhone(f.ctx, userID, session)
			return err
		},
		"BeginTotpSetup": func() error {
			_, _, _, err := f.svc.BeginTotpSetup(f.ctx, userID, session)
			return err
		},
		"VerifyTotpSetup": func() error {
			_, err := f.svc.VerifyTotpSetup(f.ctx, userID, session, "123456")
			return err
		},
		"BeginPasskeyRegistration": func() error {
			_, _, err := f.svc.BeginPasskeyRegistration(f.ctx, userID, session, "Key")
			return err
		},
		"CompletePasskeyRegistration": func() error {
			_, _, err := f.svc.CompletePasskeyRegistration(f.ctx, userID, session, "challenge", "{}", "Key", false, "", "")
			return err
		},
		"LinkIdentity": func() error {
			_, err := f.svc.LinkIdentity(f.ctx, userID, session, "code", "google", "https://app.test/cb", "", "", "")
			return err
		},
	}
}

func TestRecoveryEmailSignIn_MarksTheSessionAndHoldsOnlyIt(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	f.svc.cfg.SMSEnabled = true
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	f.repo.mu.Lock()
	f.repo.users[user.ID].PhoneNumber, f.repo.users[user.ID].PhoneVerified = "+14155550199", true
	f.repo.mu.Unlock()

	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("hold before any recovery sign-in = %d, want 0", until)
	}
	result, err := f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if amr := f.sessionAMR(t, result.AccessToken); !slices.Equal(amr, []string{AMRRecoveryEmail}) {
		t.Fatalf("the session's amr = %v, want [%s]", amr, AMRRecoveryEmail)
	}
	_, refreshed, _, err := f.svc.RefreshToken(f.ctx, result.RefreshToken, "", "", "")
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if amr := f.sessionAMR(t, refreshed); !slices.Equal(amr, []string{AMRRecoveryEmail}) {
		t.Fatalf("a refreshed session's amr = %v, want [%s]", amr, AMRRecoveryEmail)
	}
	wantUntil := f.now.Add(7 * 24 * time.Hour).UnixMilli()
	if until := f.holdUntil(t, user.ID); until != wantUntil {
		t.Fatalf("listed hold = %d, want %d", until, wantUntil)
	}

	// The session the recovery email opened, and one no host vouched for,
	// change none of the account's sign-in or recovery settings.
	for _, session := range []SessionSignIn{f.recoverySignedInNow(), {AuthTimeSec: f.now.Unix(), AMR: []string{AMRUnvouched}}} {
		for name, change := range f.heldChanges(user.ID, session) {
			var hold *RecoveryHoldError
			if err := change(); !errors.As(err, &hold) || !errors.Is(err, ErrRecoveryHold) || hold.UntilMs != wantUntil {
				t.Fatalf("%s by a %v session during the hold = %v (%+v), want a RecoveryHoldError until %d", name, session.AMR, err, hold, wantUntil)
			}
		}
	}
	// Nor can it hand a session to another device, which would not carry
	// its amr.
	qr, err := f.svc.InitiateQrLogin(f.ctx, "laptop", "agent", "203.0.113.9")
	if err != nil {
		t.Fatalf("InitiateQrLogin: %v", err)
	}
	if _, err := f.svc.ApproveQrLogin(f.ctx, qr.SessionID, true, user.ID, f.recoverySignedInNow(), "", ""); !errors.Is(err, ErrRecoverySession) {
		t.Fatalf("QR approval by a recovery session: want ErrRecoverySession, got %v", err)
	}

	// The owner, signed in with the primary email, is not held: they remove
	// the address that started the hold, and that ends it.
	if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net"); err != nil {
		t.Fatalf("the owner removes the compromised address during the hold: %v", err)
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("hold after the address that started it was removed = %d, want 0", until)
	}
}

func TestRecoveryEmailSignIn_RepeatedSignInsCannotLockTheOwnerOut(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")

	if _, err := f.signInWith(f.ctx, t, "spare@example.net"); err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	wantUntil := f.now.Add(7 * 24 * time.Hour).UnixMilli()
	// Whoever holds the mailbox signs in again and again within the hold:
	// it does not move.
	for day := 1; day <= 6; day++ {
		f.now = f.now.Add(24 * time.Hour)
		if _, err := f.signInWith(f.ctx, t, "spare@example.net"); err != nil {
			t.Fatalf("sign-in on day %d: %v", day, err)
		}
		if until := f.holdUntil(t, user.ID); until != wantUntil {
			t.Fatalf("hold after a sign-in on day %d = %d, want it still to end at %d", day, until, wantUntil)
		}
	}
	// And the owner, signed in another way, adds and removes as they please
	// throughout.
	f.add(t, user, "fresh@example.net")
	for _, addr := range []string{"fresh@example.net", "spare@example.net"} {
		if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), addr); err != nil {
			t.Fatalf("the owner removes %s during the hold: %v", addr, err)
		}
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("hold once every address is gone = %d, want 0", until)
	}
}

// recoverySecondFactorFixture is a recovery sign-in fixture in the project
// login governance governs, for an account on the governed domain.
func newRecoverySecondFactorFixture(t *testing.T, gov *LoginGovernance) (*recoveryEmailFixture, *User) {
	t.Helper()
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	scope := *ProjectScopeFromContext(f.ctx)
	scope.ProjectID = "proj-1"
	f.ctx = WithProjectScope(context.Background(), &scope)
	if gov != nil {
		f.svc.WithLoginGovernance(gov)
	}
	user := seedUser(f.repo, "owner@acme.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	return f, user
}

func TestRecoveryEmailSignIn_SecondFactorComesBeforeTheHold(t *testing.T) {
	f, user := newRecoverySecondFactorFixture(t, nil)
	seedVerifiedTotp(t, f.repo, user.ID)
	f.repo.mu.Lock()
	f.repo.users[user.ID].TotpRequired = true
	f.repo.mu.Unlock()
	const notice = "Your account was signed in to with a recovery email"

	// The code alone gets a challenge: no tokens, no hold, no notice.
	result, err := f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil || !result.TotpRequired || result.LoginChallengeID == "" || result.AccessToken != "" {
		t.Fatalf("code sign-in to a two-step account = %+v %v, want a second-factor challenge", result, err)
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("a code alone started a hold until %d", until)
	}
	signInNotices := func() int {
		n := 0
		for _, m := range f.mailedTo("owner@acme.com") {
			if m.Subject == notice {
				n++
			}
		}
		return n
	}
	if signInNotices() != 0 {
		t.Fatal("a code alone sent the sign-in notice")
	}
	// A wrong second factor starts nothing either.
	if _, err := f.svc.VerifyTotp(f.ctx, result.LoginChallengeID, "000000", "", ""); err == nil {
		t.Fatal("VerifyTotp with a wrong code: want an error")
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("a sign-in that failed its second factor started a hold until %d", until)
	}

	f.now = f.now.Add(2 * time.Minute)
	result, err = f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil || result.LoginChallengeID == "" {
		t.Fatalf("second sign-in = %+v %v", result, err)
	}
	code, err := totpGenerateCode("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	done, err := f.svc.VerifyTotp(f.ctx, result.LoginChallengeID, code, "", "")
	if err != nil || done.AccessToken == "" || done.User.ID != user.ID {
		t.Fatalf("VerifyTotp = %+v %v, want the holding account's session", done, err)
	}
	if amr := f.sessionAMR(t, done.AccessToken); !slices.Equal(amr, []string{AMRRecoveryEmail}) {
		t.Fatalf("the session the factor completed has amr %v, want [%s]", amr, AMRRecoveryEmail)
	}
	if until := f.holdUntil(t, user.ID); until != f.now.Add(7*24*time.Hour).UnixMilli() {
		t.Fatalf("hold once the factor passed = %d", until)
	}
	if n := signInNotices(); n != 1 {
		t.Fatalf("%d sign-in notices once the factor passed, want one", n)
	}
}

func TestRecoveryEmailSignIn_TenantRequire2FAAsksForTheFactor(t *testing.T) {
	f, user := newRecoverySecondFactorFixture(t, withRequire2FA())
	seedVerifiedTotp(t, f.repo, user.ID)

	result, err := f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil || !result.TotpRequired || result.LoginChallengeID == "" || result.AccessToken != "" {
		t.Fatalf("recovery sign-in under a tenant's Require2FA = %+v %v, want a challenge", result, err)
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("a challenge started a hold until %d", until)
	}
}

func TestRecoveryEmailSignIn_PolicyThatRefusesEmailCodesRefusesIt(t *testing.T) {
	f, user := newRecoverySecondFactorFixture(t, withAllowedMethods(LoginMethodPassword))
	sent := f.mailer.count()

	if _, err := f.signInWith(f.ctx, t, "spare@example.net"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("recovery sign-in under a password-only policy: want ErrPermissionDenied, got %v", err)
	}
	if until := f.holdUntil(t, user.ID); until != 0 {
		t.Fatalf("a refused sign-in started a hold until %d", until)
	}
	if f.mailer.count() != sent+1 {
		t.Fatalf("%d messages, want only the code", f.mailer.count()-sent)
	}
}

func TestRecoveryEmailSignIn_MagicLinkSignsInToTheHoldingAccount(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	f.svc.returnAllow = mustReturnAllowlist(t, "https://app.test/")
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	users := f.userCount()

	if err := f.svc.RequestMagicLink(f.ctx, "Spare@example.net", "https://app.test/finish"); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	links := f.mailedTo("spare@example.net")
	result, err := f.svc.RedeemMagicLink(f.ctx, extractTokenFromLink(t, links[len(links)-1].Text), "203.0.113.7", "test-agent")
	if err != nil || result.User.ID != user.ID || result.AccessToken == "" {
		t.Fatalf("RedeemMagicLink = %+v %v, want the holding account", result, err)
	}
	if f.userCount() != users {
		t.Fatal("the link made a new account")
	}
	if amr := f.sessionAMR(t, result.AccessToken); !slices.Equal(amr, []string{AMRRecoveryEmail}) {
		t.Fatalf("the link's session has amr %v", amr)
	}
	if until := f.holdUntil(t, user.ID); until == 0 {
		t.Fatal("the link's sign-in started no hold")
	}
}

func TestRecoveryEmailSignIn_OffMeansTheAddressSignsInToNothing(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	scope := *ProjectScopeFromContext(f.ctx)
	scope.RecoveryEmails.SignIn = false
	off := WithProjectScope(context.Background(), &scope)
	users := f.userCount()

	if _, err := f.signInWith(off, t, "spare@example.net"); !errors.Is(err, ErrEmailLoginCodeInvalid) {
		t.Fatalf("code sign-in with sign_in off: want ErrEmailLoginCodeInvalid, got %v", err)
	}
	if _, err := f.svc.completePasswordlessLogin(off, canonicalize("spare@example.net"), "magic_link", "", ""); !errors.Is(err, ErrMagicLinkInvalid) {
		t.Fatalf("link sign-in with sign_in off: want ErrMagicLinkInvalid, got %v", err)
	}
	if f.userCount() != users {
		t.Fatalf("a refused sign-in made an account: %d users, want %d", f.userCount(), users)
	}
	if _, until, _ := f.svc.ListRecoveryEmails(off, user.ID); until != 0 {
		t.Fatalf("a refused sign-in started a hold until %d", until)
	}
}

func TestRecoveryEmailSignIn_AccessGoesByTheAccountNotTheRecoveryAddress(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeAllowlist, AllowedEmails: []string{"owner@example.com"}})
	owner := seedUser(f.repo, "owner@example.com", "", StatusActive)
	outsider := seedUser(f.repo, "outsider@example.com", "", StatusActive)
	f.add(t, owner, "spare@example.net")
	f.add(t, outsider, "outsider-spare@example.net")

	// The recovery email is on no allowlist, and still receives the code and
	// signs in: the account's primary email is what the project admitted.
	result, err := f.signInWith(f.ctx, t, "spare@example.net")
	if err != nil || result.User.ID != owner.ID {
		t.Fatalf("sign-in for an admitted account = %v %v", result, err)
	}
	// An account the project no longer admits gets no way round that.
	if _, err := f.signInWith(f.ctx, t, "outsider-spare@example.net"); !errors.Is(err, ErrAccessNotAllowed) {
		t.Fatalf("sign-in for an account off the allowlist: want ErrAccessNotAllowed, got %v", err)
	}
	if _, until, _ := f.svc.ListRecoveryEmails(f.ctx, outsider.ID); until != 0 {
		t.Fatal("a refused sign-in started a hold")
	}

	// An address nobody holds is still not mailed by an allowlist project.
	sent := f.mailer.count()
	if err := f.svc.RequestEmailLoginCode(f.ctx, "stranger@example.net"); err != nil {
		t.Fatalf("RequestEmailLoginCode: %v", err)
	}
	if f.mailer.count() != sent {
		t.Fatal("a code was mailed to an address no account holds")
	}

	// A closed project mails no recovery email either.
	scope := *ProjectScopeFromContext(f.ctx)
	scope.Access = ProjectAccessConfig{Mode: AccessModeClosed}
	f.now = f.now.Add(2 * time.Minute)
	if err := f.svc.RequestEmailLoginCode(WithProjectScope(context.Background(), &scope), "spare@example.net"); err != nil {
		t.Fatalf("RequestEmailLoginCode (closed): %v", err)
	}
	if f.mailer.count() != sent {
		t.Fatal("a closed project mailed a sign-in code to a recovery email")
	}
}

func TestRecoveryEmailSignIn_RefusesAnAccountThatMayNotSignIn(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")
	f.repo.mu.Lock()
	f.repo.users[user.ID].Status = StatusDeactivated
	f.repo.mu.Unlock()

	if _, err := f.signInWith(f.ctx, t, "spare@example.net"); !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("sign-in to a deactivated account: want ErrAccountNotActive, got %v", err)
	}
	if _, until, _ := f.svc.ListRecoveryEmails(f.ctx, user.ID); until != 0 {
		t.Fatal("a refused sign-in started a hold")
	}
}

func TestProjectRecoveryEmailsConfig_Hold(t *testing.T) {
	if got := (ProjectRecoveryEmailsConfig{}).hold(); got != 7*24*time.Hour {
		t.Fatalf("default hold = %s, want 168h", got)
	}
	if got := (ProjectRecoveryEmailsConfig{HoldSeconds: 3600}).hold(); got != time.Hour {
		t.Fatalf("configured hold = %s, want 1h", got)
	}
	for _, bad := range []int{-1, 30*24*60*60 + 1} {
		cfg := ProjectConfig{RecoveryEmails: ProjectRecoveryEmailsConfig{HoldSeconds: bad}}
		if err := cfg.Validate(); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("Validate(hold_seconds=%d): want ErrInvalidArgument, got %v", bad, err)
		}
	}
	// The hold follows the configured length, not the one in force when the
	// address signed in.
	held := []*RecoveryEmail{{LastSignInAt: 1_000}, {LastSignInAt: 5_000}}
	if got := recoveryHoldUntil(held, 10*time.Second, 14_999); got != 15_000 {
		t.Fatalf("hold end = %d, want 15000", got)
	}
	if got := recoveryHoldUntil(held, 10*time.Second, 15_000); got != 0 {
		t.Fatalf("hold end at its own end = %d, want 0", got)
	}
}
