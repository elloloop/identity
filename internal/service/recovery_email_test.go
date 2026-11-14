package service

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
)

// recoveryEmailFixture is an AuthService in a project that keeps recovery
// emails, with a recording mailer and a clock the test moves, and the
// ProfileService beside it on the same store (sessions and passkeys in db)
// and clock.
type recoveryEmailFixture struct {
	svc     *AuthService
	profile *ProfileService
	repo    *fakeRepo
	db      *fakeDB
	mailer  *recordingMailer
	now     time.Time
	ctx     context.Context
}

func newRecoveryEmailFixture(t *testing.T, cfg ProjectRecoveryEmailsConfig) *recoveryEmailFixture {
	t.Helper()
	f := &recoveryEmailFixture{repo: newFakeRepo(), db: newFakeDB(), mailer: &recordingMailer{}, now: time.Unix(1_800_000_000, 0)}
	f.svc = newTestAuthService(t, f.repo)
	f.svc.mailer = f.mailer
	f.svc.nowFunc = func() time.Time { return f.now }
	f.profile = NewProfileService(f.repo, f.db, "project-a", audit.NewLogger(nil, "project-a", zap.NewNop()), zap.NewNop())
	f.profile.nowFunc = func() time.Time { return f.now }
	f.ctx = WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-a", RecoveryEmails: cfg})
	return f
}

// signedInNow is a session whose sign-in, not by a recovery email, just
// happened.
func (f *recoveryEmailFixture) signedInNow() SessionSignIn {
	return SessionSignIn{AuthTimeSec: f.now.Unix()}
}

// recoverySignedInNow is a session user's recovery email addr opened just
// now.
func (f *recoveryEmailFixture) recoverySignedInNow(t *testing.T, user *User, addr string) SessionSignIn {
	t.Helper()
	return SessionSignIn{AuthTimeSec: f.now.Unix(), AMR: []string{AMRRecoveryEmail}, RecoveryEmailID: f.recoveryEmailID(t, user.ID, addr)}
}

// recoveryEmailID is the ID of the recovery email addr userID holds.
func (f *recoveryEmailFixture) recoveryEmailID(t *testing.T, userID, addr string) string {
	t.Helper()
	held, err := f.repo.ListRecoveryEmails(f.ctx, userID)
	if err != nil {
		t.Fatalf("ListRecoveryEmails: %v", err)
	}
	for _, e := range held {
		if FoldEmail(e.Email) == FoldEmail(addr) {
			return e.ID
		}
	}
	t.Fatalf("%s holds no recovery email %s", userID, addr)
	return ""
}

var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// codeMailedTo returns the code in the last message sent to addr.
func (f *recoveryEmailFixture) codeMailedTo(t *testing.T, addr string) string {
	t.Helper()
	f.mailer.mu.Lock()
	defer f.mailer.mu.Unlock()
	for i := len(f.mailer.sent) - 1; i >= 0; i-- {
		if f.mailer.sent[i].To == addr {
			if code := sixDigits.FindString(f.mailer.sent[i].Text); code != "" {
				return code
			}
		}
	}
	t.Fatalf("no code was mailed to %s", addr)
	return ""
}

func (f *recoveryEmailFixture) mailedTo(addr string) []email.Message {
	f.mailer.mu.Lock()
	defer f.mailer.mu.Unlock()
	var out []email.Message
	for _, m := range f.mailer.sent {
		if m.To == addr {
			out = append(out, m)
		}
	}
	return out
}

// add proves addr for user and fails the test on any refusal.
func (f *recoveryEmailFixture) add(t *testing.T, user *User, addr string) {
	t.Helper()
	if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), addr); err != nil {
		t.Fatalf("RequestRecoveryEmail(%s): %v", addr, err)
	}
	if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), addr, f.codeMailedTo(t, addr)); err != nil {
		t.Fatalf("VerifyRecoveryEmail(%s): %v", addr, err)
	}
	// Past both send cooldowns, so the next request in a test is not dropped.
	f.now = f.now.Add(2 * time.Minute)
}

func TestRecoveryEmail_AddProvesTheAddressThenStoresIt(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true})
	user := seedVerified(f.repo, "owner@example.com", "")

	if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "Spare@Example.net"); err != nil {
		t.Fatalf("RequestRecoveryEmail: %v", err)
	}
	if held, _, _ := f.svc.ListRecoveryEmails(f.ctx, user.ID); len(held) != 0 {
		t.Fatalf("an unproved address is held: %#v", held)
	}
	code := f.codeMailedTo(t, "spare@example.net")

	held, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net", code)
	if err != nil {
		t.Fatalf("VerifyRecoveryEmail: %v", err)
	}
	if len(held) != 1 || held[0].Email != "spare@example.net" || held[0].VerifiedAt != f.now.UnixMilli() {
		t.Fatalf("held = %#v", held)
	}
	notices := f.mailedTo("owner@example.com")
	if len(notices) != 1 || notices[0].Subject != "A recovery email was added to your account" ||
		!strings.Contains(notices[0].Text, "spare@example.net") {
		t.Fatalf("notice to the primary address = %#v", notices)
	}
	if got := f.mailedTo("spare@example.net"); len(got) != 1 {
		t.Fatalf("the added address got %d messages, want only its code", len(got))
	}
	// The code is single-use.
	if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net", code); !errors.Is(err, ErrRecoveryEmailCodeInvalid) {
		t.Fatalf("replayed code: want ErrRecoveryEmailCodeInvalid, got %v", err)
	}
}

// An address that may sign in to the account is held to the format a
// sign-up's address is: no disposable mailbox and no non-routable domain is
// mailed a code, nor stored.
func TestRecoveryEmail_RefusesAnAddressASignUpWould(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true})
	user := seedVerified(f.repo, "owner@example.com", "")
	for _, addr := range []string{"someone@mailinator.com", "someone@example.test", "someone@intranet.local"} {
		sent := f.mailer.count()
		if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), addr); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("RequestRecoveryEmail(%s) = %v, want ErrInvalidArgument", addr, err)
		}
		if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), addr, "123456"); !errors.Is(err, ErrRecoveryEmailCodeInvalid) {
			t.Fatalf("VerifyRecoveryEmail(%s) = %v, want ErrRecoveryEmailCodeInvalid", addr, err)
		}
		if f.mailer.count() != sent {
			t.Fatalf("%s was mailed", addr)
		}
	}
}

// An account whose own address is unproven keeps no recovery email: whoever
// signed it up may not own that mailbox, and their recovery email would sign
// in to the account once the owner proved it. Nothing is mailed, and the
// account takes one once its address is proven.
func TestRecoveryEmail_RefusedWhileThePrimaryEmailIsUnproven(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true})
	user := seedUser(f.repo, "owner@example.com", "", StatusActive)
	if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "planter@example.net"); !errors.Is(err, ErrEmailVerificationRequired) {
		t.Fatalf("Request: want ErrEmailVerificationRequired, got %v", err)
	}
	if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "planter@example.net", "123456"); !errors.Is(err, ErrEmailVerificationRequired) {
		t.Fatalf("Verify: want ErrEmailVerificationRequired, got %v", err)
	}
	if f.mailer.count() != 0 {
		t.Fatalf("%d messages sent for an account whose address is unproven", f.mailer.count())
	}
	user.EmailVerified = true
	f.add(t, user, "spare@example.net")
}

func TestRecoveryEmail_RefusedWhereTheProjectKeepsNone(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{})
	user := seedVerified(f.repo, "owner@example.com", "")
	if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net"); !errors.Is(err, ErrRecoveryEmailsDisabled) {
		t.Fatalf("Request: want ErrRecoveryEmailsDisabled, got %v", err)
	}
	if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net", "123456"); !errors.Is(err, ErrRecoveryEmailsDisabled) {
		t.Fatalf("Verify: want ErrRecoveryEmailsDisabled, got %v", err)
	}
	// No project scope at all is the same refusal.
	if err := f.svc.RequestRecoveryEmail(context.Background(), user.ID, f.signedInNow(), "spare@example.net"); !errors.Is(err, ErrRecoveryEmailsDisabled) {
		t.Fatalf("Request without a scope: want ErrRecoveryEmailsDisabled, got %v", err)
	}
	if f.mailer.count() != 0 {
		t.Fatalf("%d messages sent by a project that keeps no recovery emails", f.mailer.count())
	}
}

func TestRecoveryEmail_ChangesNeedARecentSignIn(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true, ReauthMaxAgeSeconds: 600})
	user := seedVerified(f.repo, "owner@example.com", "")
	f.add(t, user, "spare@example.net")

	stale := f.now.Add(-601 * time.Second).Unix()
	fresh := f.now.Add(-600 * time.Second).Unix()
	for _, authTime := range []int64{0, stale} {
		if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, SessionSignIn{AuthTimeSec: authTime}, "other@example.net"); !errors.Is(err, ErrRecoveryReauthenticationRequired) {
			t.Fatalf("Request at auth_time %d: want ErrRecoveryReauthenticationRequired, got %v", authTime, err)
		}
		if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, SessionSignIn{AuthTimeSec: authTime}, "other@example.net", "123456"); !errors.Is(err, ErrRecoveryReauthenticationRequired) {
			t.Fatalf("Verify at auth_time %d: want ErrRecoveryReauthenticationRequired, got %v", authTime, err)
		}
		if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, SessionSignIn{AuthTimeSec: authTime}, "spare@example.net"); !errors.Is(err, ErrRecoveryReauthenticationRequired) {
			t.Fatalf("Remove at auth_time %d: want ErrRecoveryReauthenticationRequired, got %v", authTime, err)
		}
	}
	if !strings.HasPrefix(ErrRecoveryReauthenticationRequired.Error(), "reauthentication_required") {
		t.Fatalf("the refusal lost its wire token: %q", ErrRecoveryReauthenticationRequired)
	}
	if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, SessionSignIn{AuthTimeSec: fresh}, "spare@example.net"); err != nil {
		t.Fatalf("Remove at the edge of the window: %v", err)
	}
	// Listing needs no recent sign-in.
	if _, _, err := f.svc.ListRecoveryEmails(f.ctx, user.ID); err != nil {
		t.Fatalf("List: %v", err)
	}
}

func TestRecoveryEmail_AnAddressBelongsToOneAccount(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true})
	a := seedVerified(f.repo, "a@example.com", "")
	b := seedVerified(f.repo, "b@example.com", "")
	f.add(t, a, "shared@example.net")

	// Another account's recovery email and another account's primary email
	// are both mailed a code like any free address, and refused only once
	// the code proves the caller controls them.
	for _, addr := range []string{"shared@example.net", "a@example.com"} {
		if err := f.svc.RequestRecoveryEmail(f.ctx, b.ID, f.signedInNow(), addr); err != nil {
			t.Fatalf("Request(%s) told the caller about another account: %v", addr, err)
		}
		if _, err := f.svc.VerifyRecoveryEmail(f.ctx, b.ID, f.signedInNow(), addr, f.codeMailedTo(t, addr)); !errors.Is(err, ErrRecoveryEmailTaken) {
			t.Fatalf("Verify(%s) with the right code: want ErrRecoveryEmailTaken, got %v", addr, err)
		}
		f.now = f.now.Add(2 * time.Minute)
	}
	if held, _, _ := f.svc.ListRecoveryEmails(f.ctx, b.ID); len(held) != 0 {
		t.Fatalf("the refused account holds %#v", held)
	}

	// The caller's own addresses are refused before anything is mailed.
	sent := f.mailer.count()
	for _, addr := range []string{"A@example.com", "Shared@example.net"} {
		if err := f.svc.RequestRecoveryEmail(f.ctx, a.ID, f.signedInNow(), addr); !errors.Is(err, ErrRecoveryEmailTaken) {
			t.Fatalf("Request(%s) by its holder: want ErrRecoveryEmailTaken, got %v", addr, err)
		}
	}
	if f.mailer.count() != sent {
		t.Fatal("a code was mailed for an address the caller already holds")
	}

	// And no sign-up may take a recovery email as its primary address.
	if _, _, err := f.svc.resolveOrCreateUserByEmail(openProject(f.ctx), canonicalize("shared@example.net"), resolveOrCreateOpts{emailVerified: true}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("sign-up on a recovery email: want ErrAlreadyExists, got %v", err)
	}
}

// openProject returns ctx's project scope with access open, so a sign-up
// reaches the store.
func openProject(ctx context.Context) context.Context {
	scope := *ProjectScopeFromContext(ctx)
	scope.Access = ProjectAccessConfig{Mode: AccessModeOpen}
	return WithProjectScope(ctx, &scope)
}

func TestRecoveryEmail_CodeIsBoundToItsAddressAndItsAttempts(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true})
	user := seedVerified(f.repo, "owner@example.com", "")
	if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	code := f.codeMailedTo(t, "spare@example.net")
	if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "other@example.net", code); !errors.Is(err, ErrRecoveryEmailCodeInvalid) {
		t.Fatalf("the code proved another address: %v", err)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < defaultCodeMaxAttempts; i++ {
		if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net", wrong); !errors.Is(err, ErrRecoveryEmailCodeInvalid) {
			t.Fatalf("wrong guess %d: want ErrRecoveryEmailCodeInvalid, got %v", i, err)
		}
	}
	if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net", code); !errors.Is(err, ErrRecoveryEmailCodeInvalid) {
		t.Fatalf("the right code after the attempt cap: want ErrRecoveryEmailCodeInvalid, got %v", err)
	}

	// An expired code proves nothing either.
	f.now = f.now.Add(2 * time.Minute)
	if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net"); err != nil {
		t.Fatalf("second Request: %v", err)
	}
	code = f.codeMailedTo(t, "spare@example.net")
	f.now = f.now.Add(f.svc.emailCodeTTL())
	if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net", code); !errors.Is(err, ErrRecoveryEmailCodeInvalid) {
		t.Fatalf("expired code: want ErrRecoveryEmailCodeInvalid, got %v", err)
	}
	if held, _, _ := f.svc.ListRecoveryEmails(f.ctx, user.ID); len(held) != 0 {
		t.Fatalf("held = %#v, want none", held)
	}
}

func TestRecoveryEmail_CapAndSendCooldown(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true, Max: 1})
	f.svc.emailThrottle = newKeyCooldown(60_000, 0)
	user := seedVerified(f.repo, "owner@example.com", "")

	if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "first@example.net"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	// Inside the account's cooldown a second request, to any address, mails
	// nothing and answers the same.
	if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "second@example.net"); err != nil {
		t.Fatalf("throttled Request: %v", err)
	}
	if got := f.mailedTo("second@example.net"); len(got) != 0 {
		t.Fatalf("%d messages mailed inside the account's cooldown", len(got))
	}
	if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "first@example.net", f.codeMailedTo(t, "first@example.net")); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	f.now = f.now.Add(2 * time.Minute)
	if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "second@example.net"); !errors.Is(err, ErrRecoveryEmailLimit) {
		t.Fatalf("Request past the cap: want ErrRecoveryEmailLimit, got %v", err)
	}
}

func TestRecoveryEmail_RemoveTellsEveryAddress(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true})
	user := seedVerified(f.repo, "owner@example.com", "")
	f.add(t, user, "keep@example.net")
	f.add(t, user, "drop@example.net")
	before := f.mailer.count()

	held, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "Drop@example.net")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(held) != 1 || held[0].Email != "keep@example.net" {
		t.Fatalf("held after remove = %#v", held)
	}
	const subject = "A recovery email was removed from your account"
	for _, addr := range []string{"owner@example.com", "keep@example.net", "drop@example.net"} {
		got := f.mailedTo(addr)
		if len(got) == 0 || got[len(got)-1].Subject != subject || !strings.Contains(got[len(got)-1].Text, "drop@example.net") {
			t.Fatalf("%s was not told of the removal: %#v", addr, got)
		}
	}
	if f.mailer.count() != before+3 {
		t.Fatalf("%d notices sent, want 3", f.mailer.count()-before)
	}
	if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "drop@example.net"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Remove an address not held: want ErrNotFound, got %v", err)
	}

	// A project that turned the feature off still lets an owner remove.
	off := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-a"})
	if _, err := f.svc.RemoveRecoveryEmail(off, user.ID, f.signedInNow(), "keep@example.net"); err != nil {
		t.Fatalf("Remove with the feature off: %v", err)
	}
}

// listFailsAfterWriteRepo fails ListRecoveryEmails once an address has been
// added or removed, as a store that fails between a write and the read
// after it would.
type listFailsAfterWriteRepo struct {
	*fakeRepo
	written *atomic.Bool
}

func (r listFailsAfterWriteRepo) WithProject(string) Repository { return r }

func (r listFailsAfterWriteRepo) AddRecoveryEmail(ctx context.Context, e *RecoveryEmail, max int) error {
	err := r.fakeRepo.AddRecoveryEmail(ctx, e, max)
	r.written.Store(err == nil)
	return err
}

func (r listFailsAfterWriteRepo) RemoveRecoveryEmail(ctx context.Context, userID, email string, atMs int64) (int, error) {
	ended, err := r.fakeRepo.RemoveRecoveryEmail(ctx, userID, email, atMs)
	r.written.Store(err == nil)
	return ended, err
}

func (r listFailsAfterWriteRepo) ListRecoveryEmails(ctx context.Context, userID string) ([]*RecoveryEmail, error) {
	if r.written.Load() {
		return nil, errors.New("store unavailable")
	}
	return r.fakeRepo.ListRecoveryEmails(ctx, userID)
}

// An address stored or removed stays audited and announced when the list
// read after the write fails: the change happened, so the account is told,
// at its primary email (and, for a removal, the removed address) at least.
func TestRecoveryEmail_AChangeIsAuditedAndToldWhenTheListAfterItFails(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true})
	w := newRecordingAuditWriter()
	f.svc.audit = audit.NewLogger(w, "test-tenant", nil)
	user := seedVerified(f.repo, "owner@example.com", "")
	if err := f.svc.RequestRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net"); err != nil {
		t.Fatalf("RequestRecoveryEmail: %v", err)
	}
	code := f.codeMailedTo(t, "spare@example.net")
	f.svc.defaultRepo = listFailsAfterWriteRepo{fakeRepo: f.repo, written: &atomic.Bool{}}

	if _, err := f.svc.VerifyRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net", code); err == nil {
		t.Fatal("VerifyRecoveryEmail with the list unreadable: want its error")
	}
	if n := w.countByEventType(string(audit.EventRecoveryEmailAdded)); n != 1 {
		t.Fatalf("%d recovery_email_added events, want 1", n)
	}
	if got := f.mailedTo("owner@example.com"); len(got) == 0 || got[len(got)-1].Subject != "A recovery email was added to your account" {
		t.Fatalf("the primary email was not told of the addition: %#v", got)
	}

	if _, err := f.svc.RemoveRecoveryEmail(f.ctx, user.ID, f.signedInNow(), "spare@example.net"); err == nil {
		t.Fatal("RemoveRecoveryEmail with the list unreadable: want its error")
	}
	if n := w.countByEventType(string(audit.EventRecoveryEmailRemoved)); n != 1 {
		t.Fatalf("%d recovery_email_removed events, want 1", n)
	}
	for _, addr := range []string{"owner@example.com", "spare@example.net"} {
		if got := f.mailedTo(addr); len(got) == 0 || got[len(got)-1].Subject != "A recovery email was removed from your account" {
			t.Fatalf("%s was not told of the removal: %#v", addr, got)
		}
	}
}

func TestRecoveryEmail_RefusesAccountsThatKeepNone(t *testing.T) {
	f := newRecoveryEmailFixture(t, ProjectRecoveryEmailsConfig{Enabled: true})
	anon := seedUser(f.repo, "", "", StatusActive)
	anon.IsAnonymous = true
	agent := seedUser(f.repo, "", "", StatusActive)
	agent.Kind = UserKindAgent

	if err := f.svc.RequestRecoveryEmail(f.ctx, anon.ID, f.signedInNow(), "spare@example.net"); !errors.Is(err, ErrAnonymousMustUpgrade) {
		t.Fatalf("anonymous: want ErrAnonymousMustUpgrade, got %v", err)
	}
	if err := f.svc.RequestRecoveryEmail(f.ctx, agent.ID, f.signedInNow(), "spare@example.net"); !errors.Is(err, ErrAgentCredential) {
		t.Fatalf("agent: want ErrAgentCredential, got %v", err)
	}
	if err := f.svc.RequestRecoveryEmail(f.ctx, "", f.signedInNow(), "spare@example.net"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("no caller: want ErrUnauthenticated, got %v", err)
	}
	person := seedVerified(f.repo, "owner@example.com", "")
	if err := f.svc.RequestRecoveryEmail(f.ctx, person.ID, f.signedInNow(), "not an address"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("malformed address: want ErrInvalidArgument, got %v", err)
	}
	if f.mailer.count() != 0 {
		t.Fatalf("%d messages sent for refused requests", f.mailer.count())
	}
}

func TestProjectRecoveryEmailsConfig_ValidateAndDefaults(t *testing.T) {
	if got := (ProjectRecoveryEmailsConfig{}).max(); got != 5 {
		t.Fatalf("default max = %d, want 5", got)
	}
	if got := (ProjectRecoveryEmailsConfig{}).reauthMaxAge(); got != 15*time.Minute {
		t.Fatalf("default reauth window = %s, want 15m", got)
	}
	for _, bad := range []ProjectRecoveryEmailsConfig{{Max: -1}, {Max: 21}, {ReauthMaxAgeSeconds: -1}, {ReauthMaxAgeSeconds: 3601}} {
		cfg := ProjectConfig{Access: ProjectAccessConfig{Mode: AccessModeOpen}, RecoveryEmails: bad}
		if err := cfg.Validate(); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("Validate(%+v): want ErrInvalidArgument, got %v", bad, err)
		}
	}
	parsed, err := ParseProjectConfig(`{"recovery_emails":{"enabled":true,"max":3,"reauth_max_age_seconds":120}}`)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	if want := (ProjectRecoveryEmailsConfig{Enabled: true, Max: 3, ReauthMaxAgeSeconds: 120}); parsed.RecoveryEmails != want {
		t.Fatalf("parsed = %+v, want %+v", parsed.RecoveryEmails, want)
	}
}
