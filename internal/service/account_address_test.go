package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
)

func TestAccountAddressLocalPart(t *testing.T) {
	cases := []struct {
		name string
		user User
		want string
	}{
		{"username as is", User{Username: "bob"}, "bob"},
		{"username wins over email", User{Username: "bob", Email: "bob@mail.example"}, "bob"},
		{"email keeps its provider", User{Email: "bob@mail.example"}, "bob-at-mail.example"},
		{"upper case folds", User{Email: "Bob@Mail.Example"}, "bob-at-mail.example"},
		{"underscore kept, plus becomes a hyphen", User{Email: "bob_x+tag@mail.example"}, "bob_x-tag-at-mail.example"},
		{"an email on the account domain keeps the -at- form", User{Email: "bob@accounts.example.test"}, "bob-at-accounts.example.test"},
		{"other characters become hyphens", User{Email: "bob!o'k@mail.example"}, "bob-o-k-at-mail.example"},
		{"dot runs collapse", User{Username: "a..b"}, "a.b"},
		{"leading and trailing dots dropped", User{Username: ".bob."}, "bob"},
		{"no identifier", User{}, ""},
		{"a malformed email derives nothing", User{Email: "not-an-address"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, accountAddressLocalPart(&tc.user))
		})
	}
}

func TestFitAddressLocalPart(t *testing.T) {
	require.Equal(t, "bob", fitAddressLocalPart("bob", 1))
	require.Equal(t, "bob-2", fitAddressLocalPart("bob", 2))
	require.Equal(t, "bob-20", fitAddressLocalPart("bob", 20))

	long := strings.Repeat("a", 70) + "-at-mail.example"
	got := fitAddressLocalPart(long, 1)
	require.Len(t, got, maxAddressLocalPart)
	require.Equal(t, got, fitAddressLocalPart(long, 1), "deterministic")
	require.NotEqual(t, got, fitAddressLocalPart(strings.Repeat("a", 70)+"-at-other.example", 1),
		"two long identifiers sharing a prefix differ")
	require.LessOrEqual(t, len(fitAddressLocalPart(long, 17)), maxAddressLocalPart)
	require.True(t, strings.HasSuffix(fitAddressLocalPart(long, 17), "-17"))

	// Exactly at the limit is kept whole.
	exact := strings.Repeat("b", maxAddressLocalPart)
	require.Equal(t, exact, fitAddressLocalPart(exact, 1))

	// A cut that lands on a dot leaves no dot before the hash tag.
	dotted := strings.Repeat("c", 54) + "." + strings.Repeat("d", 20)
	require.NotContains(t, fitAddressLocalPart(dotted, 1), ".-")
}

func TestProjectAccountsConfig(t *testing.T) {
	cfg, err := ParseProjectConfig(`{"accounts":{"domain":" Accounts.Example.COM. "}}`)
	require.NoError(t, err)
	require.Equal(t, "accounts.example.com", cfg.Accounts.Domain)

	cfg, err = ParseProjectConfig(`{"accounts":{"domain":"bücher.example"}}`)
	require.NoError(t, err)
	require.Equal(t, "xn--bcher-kva.example", cfg.Accounts.Domain)

	cfg, err = ParseProjectConfig(`{}`)
	require.NoError(t, err)
	require.Empty(t, cfg.Accounts.Domain)

	for _, bad := range []string{"localhost", "-bad-.example", "a b.example", ".example", "a..b.example", "x-.example"} {
		_, err := ParseProjectConfig(`{"accounts":{"domain":"` + bad + `"}}`)
		require.Error(t, err, bad)
	}

	def, err := NewDefaultProjectAccounts(&config.Config{DefaultEmailDomain: "Accounts.Example.com"})
	require.NoError(t, err)
	require.Equal(t, "accounts.example.com", def.Domain)
	_, err = NewDefaultProjectAccounts(&config.Config{DefaultEmailDomain: "nodot"})
	require.Error(t, err)
}

func accountsScope(t *testing.T, domain string) context.Context {
	t.Helper()
	cfg, err := ParseProjectConfig(`{"access":{"mode":"open"},"accounts":{"domain":"` + domain + `"}}`)
	require.NoError(t, err)
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "project-a", Access: cfg.Access, Accounts: cfg.Accounts,
	})
}

func TestAccountAddress_IssuedOnceTheEmailIsVerified(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.cfg.AuthRequireVerifiedEmail = false
	ctx := accountsScope(t, "accounts.example.com")

	// A sign-up has not proven it owns the address: no address yet.
	res, err := svc.PasswordSignup(ctx, "bob@mail.example.com", accessTestPassword, "Bob", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	require.Empty(t, res.User.AccountAddress)
	u, err := repo.FindUserByEmail(ctx, "bob@mail.example.com")
	require.NoError(t, err)
	require.Empty(t, u.AccountAddress)

	// Verified, the next sign-in issues it.
	require.NoError(t, repo.UpdateUser(ctx, u.ID, map[string]any{"email_verified": true}))
	login, err := svc.PasswordLogin(ctx, "bob@mail.example.com", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.Equal(t, "bob-at-mail.example.com@accounts.example.com", login.User.AccountAddress)
}

// The duplicate-signup decoy carries the address a genuine new account would
// get, so account_address cannot tell a registered email from a new one.
func TestAccountAddress_DuplicateSignupDecoyMatches(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.cfg.AuthRequireVerifiedEmail = false
	ctx := accountsScope(t, "accounts.example.com")

	fresh, err := svc.PasswordSignup(ctx, "carol@mail.example.com", accessTestPassword, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	dup, err := svc.PasswordSignup(ctx, "carol@mail.example.com", accessTestPassword, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	require.Equal(t, fresh.User.AccountAddress, dup.User.AccountAddress)
	require.Equal(t, fresh.User.EmailVerified, dup.User.EmailVerified)

	// A decoy for a path whose genuine account is created verified (passkey
	// sign-up) carries the predicted address.
	decoy := svc.newDuplicateSignupUser("dave@mail.example.com", "dave")
	decoy.EmailVerified = true
	out, err := svc.duplicateSignupDecoyResult(ctx, decoy)
	require.NoError(t, err)
	require.Equal(t, "dave-at-mail.example.com@accounts.example.com", out.User.AccountAddress)
}

func TestAccountAddress_NoneWithoutDomain(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, `{"access":{"mode":"open"}}`)

	_, err := svc.PasswordSignup(ctx, "bob@mail.example.com", accessTestPassword, "Bob", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	u, err := repo.FindUserByEmail(ctx, "bob@mail.example.com")
	require.NoError(t, err)
	require.Empty(t, u.AccountAddress)
}

func TestAccountAddress_BackfilledAtNextSignIn(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	existing := verified(seedUser(repo, "early@mail.example.com", hashPW(t, accessTestPassword), "active"))
	require.Empty(t, existing.AccountAddress)

	ctx := accountsScope(t, "accounts.example.com")
	_, err := svc.PasswordLogin(ctx, "early@mail.example.com", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	u, err := repo.GetUser(ctx, existing.ID)
	require.NoError(t, err)
	require.Equal(t, "early-at-mail.example.com@accounts.example.com", u.AccountAddress)

	// Never rewritten: a later sign-in under another domain keeps it.
	other := accountsScope(t, "elsewhere.example.com")
	_, err = svc.PasswordLogin(other, "early@mail.example.com", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	u, err = repo.GetUser(ctx, existing.ID)
	require.NoError(t, err)
	require.Equal(t, "early-at-mail.example.com@accounts.example.com", u.AccountAddress)
}

func TestAccountAddress_ClashTakesNextSuffix(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.com")
	// A username that spells the same local part as the email below.
	taken := seedUser(repo, "", "", "active")
	require.NoError(t, repo.UpdateUser(ctx, taken.ID, map[string]any{
		"account_address": "bob-at-mail.example.com@accounts.example.com",
	}))

	u := verified(seedUser(repo, "bob@mail.example.com", "", "active"))
	ensureAccountAddress(ctx, repo, zap.NewNop(), u)
	require.Equal(t, "bob-at-mail.example.com-2@accounts.example.com", u.AccountAddress)
	stored, err := repo.GetUser(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, u.AccountAddress, stored.AccountAddress)
}

func TestAccountAddress_SkipsAnonymousAndFailuresDoNotBlock(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.com")

	anon := &User{ID: "anon", IsAnonymous: true}
	ensureAccountAddress(ctx, repo, zap.NewNop(), anon)
	require.Empty(t, anon.AccountAddress)

	failing := newErrorRepo()
	failing.failAssignAccountAddress = true
	u := verified(seedUser(failing.fakeRepo, "bob@mail.example.com", "", "active"))
	ensureAccountAddress(ctx, failing, zap.NewNop(), u)
	require.Empty(t, u.AccountAddress, "a store failure leaves the address for the next sign-in")

	// An account the store has no row for (an id the caller made up) gets
	// nothing, and nothing is written.
	ghost := &User{ID: "ghost", Email: "ghost@mail.example.com"}
	ensureAccountAddress(ctx, repo, zap.NewNop(), ghost)
	require.Empty(t, ghost.AccountAddress)
	noID := &User{Email: "noid@mail.example.com"}
	ensureAccountAddress(ctx, repo, zap.NewNop(), noID)
	require.Empty(t, noID.AccountAddress)
}

func TestAccountAddress_NeverReplacesAHeldAddress(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.com")
	u := verified(seedUser(repo, "bob@mail.example.com", "", "active"))
	held, err := repo.AssignAccountAddress(ctx, u.ID, "first@accounts.example.com")
	require.NoError(t, err)
	require.Equal(t, "first@accounts.example.com", held)

	// A stale copy of the account (read before the first assignment) asks
	// again: the stored address wins and the copy learns it.
	stale := &User{ID: u.ID, Email: u.Email, EmailVerified: true}
	ensureAccountAddress(ctx, repo, zap.NewNop(), stale)
	require.Equal(t, "first@accounts.example.com", stale.AccountAddress)
}

func TestAccountAddress_ExhaustedSuffixesEndOnTheIDSuffix(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.com")
	for attempt := 1; attempt <= maxAddressAttempts; attempt++ {
		other := seedUser(repo, "", "", "active")
		_, err := repo.AssignAccountAddress(ctx, other.ID, fitAddressLocalPart("bob-at-mail.example.com", attempt)+"@accounts.example.com")
		require.NoError(t, err)
	}
	u := verified(seedUser(repo, "bob@mail.example.com", "", "active"))
	ensureAccountAddress(ctx, repo, zap.NewNop(), u)
	require.NotEmpty(t, u.AccountAddress)
	require.True(t, strings.HasPrefix(u.AccountAddress, "bob-at-mail.example.com-"))
	require.True(t, strings.HasSuffix(u.AccountAddress, "@accounts.example.com"))
	require.NotContains(t, u.AccountAddress, "-21@")
}

func TestAccountAddress_FollowsAConfirmedEmailChange(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.com")
	u := verified(seedUser(repo, "old@mail.example.com", "", "active"))
	ensureAccountAddress(ctx, repo, zap.NewNop(), u)
	require.Equal(t, "old-at-mail.example.com@accounts.example.com", u.AccountAddress)

	u.Email = "new@mail.example.com"
	reissueAccountAddress(ctx, repo, zap.NewNop(), u)
	require.Equal(t, "new-at-mail.example.com@accounts.example.com", u.AccountAddress)

	// A username account keeps its handle whatever its email does.
	named := verified(seedUser(repo, "named@mail.example.com", "", "active"))
	named.Username = "named"
	ensureAccountAddress(ctx, repo, zap.NewNop(), named)
	named.Email = "other@mail.example.com"
	ReissueAddressAfterEmailChange(ctx, repo, zap.NewNop(), named)
	require.Equal(t, "named@accounts.example.com", named.AccountAddress)
}

func TestValidateUsernameFormat_KeepsAddressesApart(t *testing.T) {
	for _, bad := range []string{"alice-at-mail.example", ".bob", "bob.", "bo..b"} {
		require.ErrorIs(t, validateUsernameFormat(bad), ErrInvalidArgument, bad)
	}
	for _, good := range []string{"bob", "bob.smith", "bob-at", "at-bob", "b_o-b"} {
		require.NoError(t, validateUsernameFormat(good), good)
	}
}

// addressRecordingRepo records the account addresses assigned through it, for
// call sites whose accounts live in another store (the admin graph).
type addressRecordingRepo struct {
	*fakeRepo
	assigned map[string]string
}

// WithProject keeps the recorder in place when the service binds the
// request's project.
func (r *addressRecordingRepo) WithProject(string) Repository { return r }

func (r *addressRecordingRepo) AssignAccountAddress(_ context.Context, userID, address string) (string, error) {
	r.assigned[userID] = address
	return address, nil
}

func TestAccountAddress_NotIssuedToAnUnverifiedInvitee(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	repo := &addressRecordingRepo{fakeRepo: newFakeRepo(), assigned: map[string]string{}}
	svc := newTestAdminServiceWithRepo(db, repo)

	res, err := svc.InviteUser(accountsScope(t, "accounts.example.com"), "admin-1",
		"new@mail.example.com", "New", "member", "", 0, true)
	require.NoError(t, err)
	// An invitee has not yet proven they own the address, so it gets none
	// until it signs in verified.
	require.Empty(t, res.User.AccountAddress)
	require.Empty(t, repo.assigned)
}

func TestAccountAddress_IssuedToAManagedChild(t *testing.T) {
	f := newManagedChildFixture(t, true)
	res, err := f.svc.CreateManagedChildAccount(accountsScope(t, "accounts.example.com"), f.adult.ID, f.req(), "1.2.3.4", "agent/1.0")
	require.NoError(t, err)
	require.Equal(t, "kid.one@accounts.example.com", res.Child.AccountAddress)
}

func TestAccountAddress_Username(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.com")
	u := seedUser(repo, "", "", "active")
	u.Username = "bob"
	ensureAccountAddress(ctx, repo, zap.NewNop(), u)
	require.Equal(t, "bob@accounts.example.com", u.AccountAddress)
}

func TestAccountAddress_ConfirmEmailChangeReissues(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	ctx := accountsScope(t, "accounts.example.com")
	user := verified(seedUserWithPassword(t, repo, "old@mail.example.com", "Str0ng!Pass1"))
	ensureAccountAddress(ctx, repo, zap.NewNop(), user)
	require.Equal(t, "old-at-mail.example.com@accounts.example.com", user.AccountAddress)

	tok := requestAndExtractChangeToken(t, svc, repo, rec, user.ID, "new@mail.example.com", "Str0ng!Pass1")
	got, err := svc.ConfirmEmailChange(ctx, tok)
	require.NoError(t, err)
	require.Equal(t, "new-at-mail.example.com@accounts.example.com", got.AccountAddress)
	stored, err := repo.GetUser(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, got.AccountAddress, stored.AccountAddress)
}

func TestAccountAddress_KeptWhenTheProjectStopsIssuing(t *testing.T) {
	repo := newFakeRepo()
	u := verified(seedUser(repo, "old@mail.example.com", "", "active"))
	ensureAccountAddress(accountsScope(t, "accounts.example.com"), repo, zap.NewNop(), u)
	require.NotEmpty(t, u.AccountAddress)

	u.Email = "new@mail.example.com"
	reissueAccountAddress(accessScope(t, `{"access":{"mode":"open"}}`), repo, zap.NewNop(), u)
	require.Equal(t, "old-at-mail.example.com@accounts.example.com", u.AccountAddress)
}

// A username stored before the address rules (here one containing "-at-")
// still signs in: sign-in checks only the shape every stored username has.
func TestAccountAddress_LegacyUsernameStillSignsIn(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, `{"access":{"mode":"open"}}`)
	legacy := seedUser(repo, "", hashPW(t, accessTestPassword), "active")
	require.NoError(t, repo.UpdateUser(ctx, legacy.ID, map[string]any{"username": "pat-at-home"}))
	require.ErrorIs(t, validateUsernameFormat("pat-at-home"), ErrInvalidArgument, "no new username may take it")

	res, err := svc.PasswordLogin(ctx, "pat-at-home", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.Equal(t, legacy.ID, res.User.ID)
}

func TestAccountAddress_IssuedOnRefresh(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	open := accessScope(t, `{"access":{"mode":"open"}}`)
	verified(seedUser(repo, "early@mail.example.com", hashPW(t, accessTestPassword), "active"))
	login, err := svc.PasswordLogin(open, "early@mail.example.com", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.Empty(t, login.User.AccountAddress)

	// The project configures a domain while the session is live: the next
	// refresh issues the address without a new sign-in.
	ctx := accountsScope(t, "accounts.example.com")
	_, _, _, err = svc.RefreshToken(ctx, login.RefreshToken, "1.2.3.4", "agent")
	require.NoError(t, err)
	u, err := repo.FindUserByEmail(ctx, "early@mail.example.com")
	require.NoError(t, err)
	require.Equal(t, "early-at-mail.example.com@accounts.example.com", u.AccountAddress)
}

func TestProjectAccountsConfig_DomainFitsAnAddress(t *testing.T) {
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + ".example"
	require.Greater(t, len(long), maxAccountDomain)
	_, err := ParseProjectConfig(`{"accounts":{"domain":"` + long + `"}}`)
	require.Error(t, err)
}

// verified marks a seeded account's email verified: an address that spells an
// email is issued only once the email is.
func verified(u *User) *User {
	u.EmailVerified = true
	return u
}

// A role name, or a legacy username that spells an email-derived address,
// never takes its plain address: it gets the id form, which nobody else can
// derive.
func TestAccountAddress_RoleNamesAndLegacySeparatorsTakeTheIDForm(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.test")
	for _, name := range []string{"postmaster", "admin", "pat-at-mail.example.test"} {
		u := seedUser(repo, "", "", "active")
		u.Username = name
		ensureAccountAddress(ctx, repo, zap.NewNop(), u)
		sum := sha256.Sum256([]byte(u.ID))
		want := name + "-" + hex.EncodeToString(sum[:4]) + "@accounts.example.test"
		require.Equal(t, want, u.AccountAddress, name)
	}
	require.ErrorIs(t, validateUsernameFormat("postmaster"), ErrInvalidArgument)
	require.ErrorIs(t, validateUsernameFormat("www"), ErrInvalidArgument)
	require.NoError(t, validateUsernameFormat("postmasters"))
}

// A legacy username the derivation would change takes the id form, so it
// cannot take the plain address another username owns.
func TestAccountAddress_ChangedLegacyUsernameTakesTheIDForm(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.test")
	for name, base := range map[string]string{"bob.": "bob", "...": unnamedLocalPart} {
		u := seedUser(repo, "", "", "active")
		u.Username = name
		ensureAccountAddress(ctx, repo, zap.NewNop(), u)
		sum := sha256.Sum256([]byte(u.ID))
		require.Equal(t, base+"-"+hex.EncodeToString(sum[:4])+"@accounts.example.test", u.AccountAddress, name)
	}
}

// A guardian's rename re-derives the child's address, so the retired handle
// (often the child's real name) stops showing.
func TestAccountAddress_FollowsAManagedChildRename(t *testing.T) {
	ctx := accountsScope(t, "accounts.example.test")
	f := newGuardianFixture(ctx, t)
	ensureAccountAddress(ctx, f.repo, zap.NewNop(), f.child)
	require.Equal(t, "kid.one@accounts.example.test", f.child.AccountAddress)

	child, err := f.svc.SetManagedChildUsername(ctx, f.guardian.ID, f.child.ID, "kid.two", strongPW, "", "")
	require.NoError(t, err)
	require.Equal(t, "kid.two@accounts.example.test", child.AccountAddress)
	stored, err := f.repo.GetUser(ctx, f.child.ID)
	require.NoError(t, err)
	require.Equal(t, "kid.two@accounts.example.test", stored.AccountAddress)
}

// ConfirmEmailChange on a username account leaves its username address.
func TestAccountAddress_UsernameAccountKeepsItsAddressOnEmailChange(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	ctx := accountsScope(t, "accounts.example.com")
	user := verified(seedUserWithPassword(t, repo, "named@mail.example.com", "Str0ng!Pass1"))
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"username": "named"}))
	user.Username = "named"
	ensureAccountAddress(ctx, repo, zap.NewNop(), user)
	require.Equal(t, "named@accounts.example.com", user.AccountAddress)

	tok := requestAndExtractChangeToken(t, svc, repo, rec, user.ID, "other@mail.example.com", "Str0ng!Pass1")
	got, err := svc.ConfirmEmailChange(ctx, tok)
	require.NoError(t, err)
	require.Equal(t, "named@accounts.example.com", got.AccountAddress)
	stored, err := repo.GetUser(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, "named@accounts.example.com", stored.AccountAddress)
}

// The decoy predicts the id form where a real account would take it.
func TestPredictedAccountAddress_FollowsTheUnsafeRule(t *testing.T) {
	ctx := accountsScope(t, "accounts.example.test")
	u := &User{ID: "u-1", Username: "postmaster"}
	sum := sha256.Sum256([]byte("u-1"))
	require.Equal(t, "postmaster-"+hex.EncodeToString(sum[:4])+"@accounts.example.test", predictedAccountAddress(ctx, u))
	v := &User{ID: "u-2", Email: "bob@mail.example", EmailVerified: true}
	require.Equal(t, "bob-at-mail.example@accounts.example.test", predictedAccountAddress(ctx, v))
}
