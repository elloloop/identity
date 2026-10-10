package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
)

func signupScope(t *testing.T, configJSON string) context.Context {
	t.Helper()
	cfg, err := ParseProjectConfig(configJSON)
	require.NoError(t, err)
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "project-a", Access: cfg.Access, Accounts: cfg.Accounts,
	})
}

func TestProjectAccountsConfig_SignupModes(t *testing.T) {
	cfg, err := ParseProjectConfig(`{"accounts":{"email_signup":" Admin ","username_signup":"SELF"}}`)
	require.NoError(t, err)
	require.Equal(t, SignupAdmin, cfg.Accounts.emailSignup())
	require.Equal(t, SignupSelf, cfg.Accounts.usernameSignup())

	cfg, err = ParseProjectConfig(`{}`)
	require.NoError(t, err)
	require.Equal(t, SignupSelf, cfg.Accounts.emailSignup(), "email self-signup stays the default")
	require.Equal(t, SignupOff, cfg.Accounts.usernameSignup(), "usernames are off unless chosen")

	for _, bad := range []string{`{"accounts":{"email_signup":"open"}}`, `{"accounts":{"username_signup":"yes"}}`} {
		_, err := ParseProjectConfig(bad)
		require.Error(t, err, bad)
	}

	def, err := NewDefaultProjectAccounts(&config.Config{DefaultProjectEmailSignup: "off", DefaultProjectUsernameSignup: "admin"})
	require.NoError(t, err)
	require.Equal(t, SignupOff, def.emailSignup())
	require.Equal(t, SignupAdmin, def.usernameSignup())
	_, err = NewDefaultProjectAccounts(&config.Config{DefaultProjectUsernameSignup: "everyone"})
	require.Error(t, err)

	require.Equal(t, SignupSelf, accountsFor(nil).emailSignup())
	require.Equal(t, SignupOff, accountsFor(nil).usernameSignup())
}

func TestEmailSignup_AdminOnlyAndOff(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)

	admin := signupScope(t, `{"access":{"mode":"open"},"accounts":{"email_signup":"admin"}}`)
	_, err := svc.PasswordSignup(admin, "new@mail.example.com", accessTestPassword, "", "", 0, "", EmailLinkParams{})
	require.ErrorIs(t, err, ErrSignupByInvitationOnly)

	off := signupScope(t, `{"access":{"mode":"open"},"accounts":{"email_signup":"off"}}`)
	_, err = svc.PasswordSignup(off, "new@mail.example.com", accessTestPassword, "", "", 0, "", EmailLinkParams{})
	require.ErrorIs(t, err, ErrAccountKindOff)

	self := signupScope(t, `{"access":{"mode":"open"},"accounts":{"email_signup":"self"}}`)
	_, err = svc.PasswordSignup(self, "new@mail.example.com", accessTestPassword, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
}

func TestEmailSignup_AdminOnly_ExistingAccountsStillSignIn(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	seedUser(repo, "made@mail.example.com", hashPW(t, accessTestPassword), "active")
	admin := signupScope(t, `{"access":{"mode":"open"},"accounts":{"email_signup":"admin"}}`)
	_, err := svc.PasswordLogin(admin, "made@mail.example.com", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
}

func TestEmailSignup_AdminOnly_CodesOnlyToExistingAccounts(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	seedUser(repo, "made@mail.example.com", "", "active")

	admin := signupScope(t, `{"access":{"mode":"open"},"accounts":{"email_signup":"admin"}}`)
	require.False(t, svc.accessAllowsCodeSend(admin, canonicalize("stranger@mail.example.com")))
	require.True(t, svc.accessAllowsCodeSend(admin, canonicalize("made@mail.example.com")))

	allow := signupScope(t, `{"access":{"mode":"allowlist","allowed_domains":["mail.example.com"]},"accounts":{"email_signup":"admin"}}`)
	require.False(t, svc.accessAllowsCodeSend(allow, canonicalize("stranger@mail.example.com")))
	require.True(t, svc.accessAllowsCodeSend(allow, canonicalize("made@mail.example.com")))

	self := signupScope(t, `{"access":{"mode":"open"}}`)
	require.True(t, svc.accessAllowsCodeSend(self, canonicalize("stranger@mail.example.com")))
}

func TestInviteUser_EmailOff(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminService(db)

	off := signupScope(t, `{"access":{"mode":"open"},"accounts":{"email_signup":"off"}}`)
	_, err := svc.InviteUser(off, "admin-1", "new@mail.example.com", "New", "member", "", 0, true)
	require.ErrorIs(t, err, ErrAccountKindOff)

	admin := signupScope(t, `{"access":{"mode":"open"},"accounts":{"email_signup":"admin"}}`)
	_, err = svc.InviteUser(admin, "admin-1", "new@mail.example.com", "New", "member", "", 0, true)
	require.NoError(t, err, "an admin creates email accounts when email_signup is admin")
}

func TestCreateUsernameUser(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("member-1", "member@test.com", "Member", "member", "active")
	repo := newFakeRepo()
	svc := newTestAdminServiceWithRepo(db, repo)

	off := signupScope(t, `{"access":{"mode":"open"}}`)
	_, err := svc.CreateUsernameUser(off, "admin-1", "bob", "Bob", "member")
	require.ErrorIs(t, err, ErrAccountKindOff, "usernames are off by default")

	for _, mode := range []string{`"closed"`, `"allowlist","allowed_domains":["mail.example.com"]`} {
		refused := signupScope(t, `{"access":{"mode":`+mode+`},"accounts":{"username_signup":"admin"}}`)
		_, err := svc.CreateUsernameUser(refused, "admin-1", "bob", "", "")
		require.ErrorIs(t, err, ErrAccessNotAllowed, "an account that could never sign in is refused under %s", mode)
	}

	ctx := signupScope(t, `{"access":{"mode":"invite"},"accounts":{"domain":"accounts.example.com","username_signup":"admin"}}`)
	_, err = svc.CreateUsernameUser(ctx, "member-1", "bob", "Bob", "member")
	require.Error(t, err, "only an admin")

	res, err := svc.CreateUsernameUser(ctx, "admin-1", " Bob ", "", "")
	require.NoError(t, err)
	require.Equal(t, "bob", res.User.Username)
	require.Equal(t, "bob", res.User.Name)
	require.Equal(t, "member", res.User.Role)
	require.Equal(t, StatusActive, res.User.Status)
	require.Empty(t, res.User.Email)
	require.Equal(t, "bob@accounts.example.com", res.User.AccountAddress)
	require.NotEmpty(t, res.TemporaryPassword)
	require.Empty(t, res.User.PasswordHash, "the hash never leaves the service")

	stored, err := repo.FindUserByUsername(ctx, "bob")
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.NotEmpty(t, stored.PasswordHash)

	_, err = svc.CreateUsernameUser(ctx, "admin-1", "bob", "", "")
	require.ErrorIs(t, err, ErrAlreadyExists)
	_, err = svc.CreateUsernameUser(ctx, "admin-1", "bob-at-mail.example", "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = svc.CreateUsernameUser(ctx, "admin-1", "carol", "", "owner")
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestUsernameSignup(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := signupScope(t, `{"access":{"mode":"open"},"accounts":{"domain":"accounts.example.com","username_signup":"self"}}`)

	res, err := svc.UsernameSignup(ctx, "Bob", accessTestPassword, "Bob B", 0, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.Equal(t, "bob", res.User.Username)
	require.Equal(t, "Bob B", res.User.Name)
	require.Empty(t, res.User.Email)
	require.Equal(t, "bob@accounts.example.com", res.User.AccountAddress)

	stored, err := repo.FindUserByUsername(ctx, "bob")
	require.NoError(t, err)
	require.Equal(t, "bob@accounts.example.com", stored.AccountAddress)

	// The username signs in through PasswordLogin.
	login, err := svc.PasswordLogin(ctx, "bob", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.Equal(t, res.User.ID, login.User.ID)

	// Taken usernames are reported as taken.
	_, err = svc.UsernameSignup(ctx, "bob", accessTestPassword, "", 0, "", "")
	require.ErrorIs(t, err, ErrAlreadyExists)

	_, err = svc.UsernameSignup(ctx, "x", accessTestPassword, "", 0, "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = svc.UsernameSignup(ctx, "carol", "", "", 0, "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = svc.UsernameSignup(ctx, "carol", "short", "", 0, "", "")
	require.ErrorIs(t, err, ErrWeakPassword)
}

func TestUsernameSignup_Refusals(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	cases := []struct {
		name   string
		config string
		want   error
	}{
		{"off by default", `{"access":{"mode":"open"}}`, ErrAccountKindOff},
		{"admin only", `{"access":{"mode":"open"},"accounts":{"username_signup":"admin"}}`, ErrSignupByInvitationOnly},
		{"invite mode", `{"access":{"mode":"invite"},"accounts":{"username_signup":"self"}}`, ErrSignupByInvitationOnly},
		{"closed mode", `{"access":{"mode":"closed"},"accounts":{"username_signup":"self"}}`, ErrAccessNotAllowed},
		{"allowlist has no email to match", `{"access":{"mode":"allowlist","allowed_domains":["mail.example.com"]},"accounts":{"username_signup":"self"}}`, ErrAccessNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.UsernameSignup(signupScope(t, tc.config), "dave", accessTestPassword, "", 0, "", "")
			require.ErrorIs(t, err, tc.want)
		})
	}

	svc.cfg.PasswordSignupEnabled = false
	_, err := svc.UsernameSignup(signupScope(t, `{"access":{"mode":"open"},"accounts":{"username_signup":"self"}}`), "dave", accessTestPassword, "", 0, "", "")
	require.ErrorIs(t, err, ErrSignupDisabled)
}

func TestUsernameSignup_ChildIsAGuardiansToCreate(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	enableAgeGate(t, svc, false)
	ctx := signupScope(t, `{"access":{"mode":"open"},"accounts":{"username_signup":"self"}}`)
	_, err := svc.UsernameSignup(ctx, "kiddo", accessTestPassword, "", dobAgeMs(8), "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = svc.UsernameSignup(ctx, "grownup", accessTestPassword, "", dobAgeMs(30), "", "")
	require.NoError(t, err)
}

func TestUsernameSignup_Throttled(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.signupThrottle = newKeyCooldown(60_000, 0)
	ctx := signupScope(t, `{"access":{"mode":"open"},"accounts":{"username_signup":"self"}}`)

	// Spend the username's bucket.
	require.True(t, svc.signupThrottle.allow(usernameThrottleKey("project-a", "erin"), svc.nowMs()))
	_, err := svc.UsernameSignup(ctx, "erin", accessTestPassword, "", 0, "", "")
	require.ErrorIs(t, err, ErrSignupThrottled)

	// Other buckets are untouched: another username, the same username in
	// another project, and the same string as an email key.
	_, err = svc.UsernameSignup(ctx, "frank", accessTestPassword, "", 0, "", "")
	require.NoError(t, err)
	require.True(t, svc.signupThrottle.allow(usernameThrottleKey("project-b", "erin"), svc.nowMs()))
	require.True(t, svc.signupThrottle.allow("erin", svc.nowMs()))
}

func TestValidateUsernameFormat_ReservedRoleNames(t *testing.T) {
	for _, name := range []string{"admin", "postmaster", "abuse", "webmaster", "noreply"} {
		require.ErrorIs(t, validateUsernameFormat(name), ErrInvalidArgument, name)
	}
	require.NoError(t, validateUsernameFormat("admins"))
}

// One login-time rule for username accounts, the same on sign-in and refresh.
func TestUsernameAccount_AccessRuleOnSignInAndRefresh(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	open := signupScope(t, `{"access":{"mode":"open"},"accounts":{"username_signup":"self"}}`)
	res, err := svc.UsernameSignup(open, "gina", accessTestPassword, "", 0, "", "")
	require.NoError(t, err)

	// The project is closed afterwards: the self-signed-up account can
	// neither sign in nor refresh.
	closed := signupScope(t, `{"access":{"mode":"closed"},"accounts":{"username_signup":"self"}}`)
	_, err = svc.PasswordLogin(closed, "gina", accessTestPassword, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
	_, _, _, err = svc.RefreshToken(closed, res.RefreshToken, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
	allow := signupScope(t, `{"access":{"mode":"allowlist","allowed_domains":["mail.example.com"]}}`)
	_, err = svc.PasswordLogin(allow, "gina", accessTestPassword, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrAccessNotAllowed)

	// A wrong password still gets the generic refusal under closed, so the
	// access refusal is no oracle for a caller without the password.
	_, err = svc.PasswordLogin(closed, "gina", "Wr0ng!Passw0rd", "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrUnauthenticated)

	// The workplace recipe: invite mode, admin-made username accounts sign in
	// and refresh.
	invite := signupScope(t, `{"access":{"mode":"invite"},"accounts":{"email_signup":"off","username_signup":"admin"}}`)
	login, err := svc.PasswordLogin(invite, "gina", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	_, _, _, err = svc.RefreshToken(invite, login.RefreshToken, "1.2.3.4", "agent")
	require.NoError(t, err)

	// A managed child keeps signing in and refreshing under closed: its
	// guardian settled whether it may exist.
	child := seedManagedChild(t, repo, "kid.closed", dobAgeMs(9))
	seedGuardianEdge(context.Background(), t, repo, res.User.ID, child.ID)
	kid, err := svc.PasswordLogin(closed, "kid.closed", strongPW, "1.2.3.4", "agent")
	require.NoError(t, err)
	_, _, _, err = svc.RefreshToken(closed, kid.RefreshToken, "1.2.3.4", "agent")
	require.NoError(t, err)
}

func TestUsernameSignup_RefusedUnderADenyLayer(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	ctx := signupScope(t, `{"access":{"mode":"open","block_public_email_domains":true},"accounts":{"username_signup":"self"}}`)
	_, err := svc.UsernameSignup(ctx, "hank", accessTestPassword, "", 0, "", "")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
}

// A username account that also has an email is judged by that email when it
// signs in by username, exactly as on refresh.
func TestUsernameAccount_WithEmailJudgedByEmail(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	open := signupScope(t, `{"access":{"mode":"open"},"accounts":{"username_signup":"self"}}`)
	res, err := svc.UsernameSignup(open, "ivan", accessTestPassword, "", 0, "", "")
	require.NoError(t, err)
	require.NoError(t, repo.UpdateUser(open, res.User.ID, map[string]any{"email": "ivan@other.example.com"}))

	allow := signupScope(t, `{"access":{"mode":"allowlist","allowed_domains":["mail.example.com"]}}`)
	_, err = svc.PasswordLogin(allow, "ivan", accessTestPassword, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrAccessNotAllowed)

	listed := signupScope(t, `{"access":{"mode":"allowlist","allowed_domains":["other.example.com"]}}`)
	_, err = svc.PasswordLogin(listed, "ivan", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
}

func TestValidateUsernameFormat_RefusesTheIDFormTag(t *testing.T) {
	require.ErrorIs(t, validateUsernameFormat("bob-1a2b3c4d"), ErrInvalidArgument)
	require.NoError(t, validateUsernameFormat("bob-1a2b3c4"))
	require.NoError(t, validateUsernameFormat("bob-cafebabe1"))
}

// A username account cannot become an email account by adding an email where
// people may not create email accounts themselves.
func TestUsernameAccount_CannotAddAnEmailWhereEmailSignupIsNotSelf(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	for mode, want := range map[string]error{"admin": ErrSignupByInvitationOnly, "off": ErrAccountKindOff} {
		ctx := signupScope(t, `{"access":{"mode":"open"},"accounts":{"username_signup":"self","email_signup":"`+mode+`"}}`)
		res, err := svc.UsernameSignup(ctx, "jo-"+mode, accessTestPassword, "", 0, "", "")
		require.NoError(t, err)
		err = svc.RequestEmailChange(ctx, res.User.ID, "jo@mail.example.test", accessTestPassword)
		require.ErrorIs(t, err, want, mode)
	}
	ctx := signupScope(t, `{"access":{"mode":"open"},"accounts":{"username_signup":"self"}}`)
	res, err := svc.UsernameSignup(ctx, "jo-self", accessTestPassword, "", 0, "", "")
	require.NoError(t, err)
	require.NoError(t, svc.RequestEmailChange(ctx, res.User.ID, "jo@mail.example.test", accessTestPassword))
}

// After an IP has been told GATEWAY_RATE_LIMIT_USERNAME_TAKEN_PER_IP times that a
// username is taken, every UsernameSignup from it is throttled, free name or
// not, so the refusal reveals nothing more.
func TestUsernameSignup_TakenAnswersAreBudgetedPerIP(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.usernameProbes = newProbeBudget(60_000, 2)
	ctx := signupScope(t, `{"access":{"mode":"open"},"accounts":{"username_signup":"self"}}`)
	_, err := svc.UsernameSignup(ctx, "kim", accessTestPassword, "", 0, "", "198.51.100.7")
	require.NoError(t, err)

	for i := 0; i < 2; i++ {
		_, err = svc.UsernameSignup(ctx, "kim", accessTestPassword, "", 0, "", "198.51.100.7")
		require.ErrorIs(t, err, ErrAlreadyExists)
	}
	_, err = svc.UsernameSignup(ctx, "kim", accessTestPassword, "", 0, "", "198.51.100.7")
	require.ErrorIs(t, err, ErrSignupThrottled, "budget spent: a taken name is throttled")
	_, err = svc.UsernameSignup(ctx, "lee", accessTestPassword, "", 0, "", "198.51.100.7")
	require.ErrorIs(t, err, ErrSignupThrottled, "budget spent: a free name is throttled the same way")

	// Another IP is unaffected.
	_, err = svc.UsernameSignup(ctx, "lee", accessTestPassword, "", 0, "", "198.51.100.8")
	require.NoError(t, err)
}

func TestProbeBudget_ReserveRefundWindow(t *testing.T) {
	b := newProbeBudget(1000, 1)
	require.True(t, b.reserve("ip", 0))
	require.False(t, b.reserve("ip", 500), "spent")
	b.refund("ip", 600)
	require.True(t, b.reserve("ip", 700), "a refunded unit can be reserved again")
	require.True(t, b.reserve("ip", 1500), "a new window")
	require.True(t, b.reserve("", 0), "no IP, no budget")
	require.True(t, (*probeBudget)(nil).reserve("ip", 0))
}

// Parallel requests from one IP cannot all pass the budget together: at most
// limit of them reach the "taken" answer.
func TestUsernameSignup_ParallelTakenAnswersStayWithinTheBudget(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.usernameProbes = newProbeBudget(60_000, 3)
	svc.signupThrottle = newKeyCooldown(0, 0)
	ctx := signupScope(t, `{"access":{"mode":"open"},"accounts":{"username_signup":"self"}}`)
	_, err := svc.UsernameSignup(ctx, "taken", accessTestPassword, "", 0, "", "")
	require.NoError(t, err)

	const n = 20
	var mu sync.Mutex
	taken := 0
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.UsernameSignup(ctx, "taken", accessTestPassword, "", 0, "", "198.51.100.9")
			if errors.Is(err, ErrAlreadyExists) {
				mu.Lock()
				taken++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.LessOrEqual(t, taken, 3)
}

func TestProbeBudget_StaysBounded(t *testing.T) {
	b := newProbeBudget(1_000_000, 1)
	for i := 0; i < probeBudgetMaxSize+10; i++ {
		b.reserve(fmt.Sprintf("ip-%d", i), 0)
	}
	require.LessOrEqual(t, len(b.spent), probeBudgetMaxSize)
}
