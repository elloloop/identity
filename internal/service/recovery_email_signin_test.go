package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
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

func TestRecoveryEmailSignIn_HoldsRecoverySettings(t *testing.T) {
	f := newRecoverySignInFixture(t, ProjectAccessConfig{Mode: AccessModeOpen})
	f.svc.cfg.SMSEnabled = true
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	f.add(t, user, "spare@example.net")

	if _, until, err := f.svc.ListRecoveryEmails(f.ctx, user.ID); err != nil || until != 0 {
		t.Fatalf("hold before any recovery sign-in = %d %v, want 0", until, err)
	}
	if _, err := f.signInWith(f.ctx, t, "spare@example.net"); err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	wantUntil := f.now.Add(7 * 24 * time.Hour).UnixMilli()

	var hold *RecoveryHoldError
	_, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net")
	if !errors.As(err, &hold) || !errors.Is(err, ErrRecoveryHold) || hold.UntilMs != wantUntil {
		t.Fatalf("Remove during the hold = %v (%+v), want a RecoveryHoldError until %d", err, hold, wantUntil)
	}
	if err := f.svc.RequestPhoneVerification(f.ctx, user.ID, "+14155550123"); !errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("RequestPhoneVerification during the hold: want ErrRecoveryHold, got %v", err)
	}
	if _, err := f.svc.VerifyPhoneCode(f.ctx, user.ID, "+14155550123", "123456"); !errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("VerifyPhoneCode during the hold: want ErrRecoveryHold, got %v", err)
	}
	if _, until, err := f.svc.ListRecoveryEmails(f.ctx, user.ID); err != nil || until != wantUntil {
		t.Fatalf("listed hold = %d %v, want %d", until, err, wantUntil)
	}

	// A sign-in by the primary email starts no hold and ends none.
	f.now = f.now.Add(2 * time.Minute)
	if _, err := f.signInWith(f.ctx, t, "owner@example.com"); err != nil {
		t.Fatalf("sign-in by the primary email: %v", err)
	}
	if _, until, _ := f.svc.ListRecoveryEmails(f.ctx, user.ID); until != wantUntil {
		t.Fatalf("hold after a primary sign-in = %d, want %d", until, wantUntil)
	}

	f.now = time.UnixMilli(wantUntil)
	if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net"); err != nil {
		t.Fatalf("Remove once the hold has ended: %v", err)
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
