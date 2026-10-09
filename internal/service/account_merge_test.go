package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/jwt"
)

// mergeFixture: a Gmail-style account (the survivor, signed up by OAuth: no
// password, an email-derived address) and a native username account with a
// password and its own address.
func mergeFixture(t *testing.T) (*AuthService, *fakeRepo, *User, *User, context.Context) {
	t.Helper()
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.cfg.AccountMergeEnabled = true
	ctx := accountsScope(t, "accounts.example.test")
	survivor := seedUser(repo, "bob@mail.example.test", "", StatusActive)
	survivor.EmailVerified = true
	survivor.AccountAddress = "bob-at-mail.example.test@accounts.example.test"
	native := seedUser(repo, "", hashPW(t, accessTestPassword), StatusActive)
	native.Username = "bob"
	native.AccountAddress = "bob@accounts.example.test"
	return svc, repo, survivor, native, ctx
}

func TestMergeAccounts_TakesUsernamePasswordAndAddress(t *testing.T) {
	svc, repo, survivor, native, ctx := mergeFixture(t)
	other := *native

	merged, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", true)
	require.NoError(t, err)
	require.Equal(t, survivor.ID, merged.ID)
	require.Equal(t, "bob", merged.Username)
	require.Equal(t, "bob@accounts.example.test", merged.AccountAddress)
	require.NotEmpty(t, merged.PasswordHash, "the survivor gains the password the username used")

	retired, err := repo.GetUser(ctx, other.ID)
	require.NoError(t, err)
	require.Equal(t, StatusDeactivated, retired.Status)
	require.Equal(t, survivor.ID, retired.MergedIntoUserID)
	require.Empty(t, retired.Username)
	require.Equal(t, "bob-at-mail.example.test@accounts.example.test", retired.AccountAddress,
		"the survivor's old address stays reserved on the retired account")

	// The username now signs in to the survivor.
	login, err := svc.PasswordLogin(ctx, "bob", accessTestPassword, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.Equal(t, survivor.ID, login.User.ID)
}

func TestMergeAccounts_KeepsTheSurvivorsOwnWhenItHasThem(t *testing.T) {
	svc, repo, survivor, native, ctx := mergeFixture(t)
	survivor.Username = "robert"
	survivor.PasswordHash = hashPW(t, "An0ther!Passw0rd")

	merged, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", false)
	require.NoError(t, err)
	require.Equal(t, "robert", merged.Username)
	require.Equal(t, "bob-at-mail.example.test@accounts.example.test", merged.AccountAddress)
	retired, _ := repo.GetUser(ctx, native.ID)
	require.Equal(t, "bob", retired.Username, "a username the survivor does not take stays on the retired account")
	require.Equal(t, "bob@accounts.example.test", retired.AccountAddress)
}

func TestMergeAccounts_ProofAndRefusals(t *testing.T) {
	svc, repo, survivor, native, ctx := mergeFixture(t)

	_, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", "Wr0ng!Passw0rd", "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "nobody", accessTestPassword, "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrUnauthenticated, "an unknown identifier gets the same refusal")
	_, err = svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "", "", "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrInvalidArgument)

	native.TotpRequired = true
	_, err = svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrMergeRefused)
	native.TotpRequired = false

	// Into itself.
	_, err = svc.MergeAccounts(ctx, native.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrMergeRefused)

	// A guardian's account is not merged away from its children.
	child := seedUser(repo, "", "", StatusActive)
	seedGuardianEdge(ctx, t, repo, native.ID, child.ID)
	_, err = svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrMergeRefused)

	// Nothing changed on a refusal.
	still, _ := repo.GetUser(ctx, native.ID)
	require.Equal(t, StatusActive, still.Status)
	require.Equal(t, "bob", still.Username)
}

func TestMergeAccounts_RetiredAccountNoLongerSignsIn(t *testing.T) {
	svc, _, survivor, _, ctx := mergeFixture(t)
	survivor.Username = "robert"
	survivor.PasswordHash = hashPW(t, "An0ther!Passw0rd")
	_, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", false)
	require.NoError(t, err)
	_, err = svc.PasswordLogin(ctx, "bob", accessTestPassword, "203.0.113.10", "agent")
	require.Error(t, err, "the retired account's own credentials no longer sign in")
}

func TestMergeUsers_AdminOnlyNoPassword(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@example.test", "Admin", "admin", "active")
	db.addUser("member-1", "member@example.test", "Member", "member", "active")
	repo := newFakeRepo()
	svc := newTestAdminServiceWithRepo(db, repo)
	ctx := accountsScope(t, "accounts.example.test")
	survivor := seedUser(repo, "a@mail.example.test", "", StatusActive)
	other := seedUser(repo, "", hashPW(t, accessTestPassword), StatusActive)
	other.Username = "ann"

	_, err := svc.MergeUsers(ctx, "member-1", survivor.ID, other.ID, false)
	require.Error(t, err)
	merged, err := svc.MergeUsers(ctx, "admin-1", survivor.ID, other.ID, false)
	require.NoError(t, err)
	require.Equal(t, "ann", merged.Username)
	retired, _ := repo.GetUser(ctx, other.ID)
	require.Equal(t, StatusDeactivated, retired.Status)
	_, err = svc.MergeUsers(ctx, "admin-1", survivor.ID, "missing", false)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestReactivateUser_RefusesAMergedAccount(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@example.test", "Admin", "admin", "active")
	db.addUser("gone-1", "gone@example.test", "Gone", "member", "deactivated")
	db.nodes["gone-1"].Payload[ufMergedInto] = "survivor-1"
	svc := newTestAdminService(db)
	err := svc.ReactivateUser(context.Background(), "admin-1", "gone-1")
	require.ErrorIs(t, err, ErrMergeRefused)
}

func TestMergeAccounts_OffByDefault(t *testing.T) {
	svc, _, survivor, _, ctx := mergeFixture(t)
	svc.cfg.AccountMergeEnabled = false
	_, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrAccountMergeDisabled)
}

// The proof is the whole password sign-in check, so an account a sign-in
// would refuse cannot be merged either.
func TestMergeAccounts_UsesTheSignInGates(t *testing.T) {
	t.Run("closed project", func(t *testing.T) {
		svc, _, survivor, _, _ := mergeFixture(t)
		closed := signupScope(t, `{"access":{"mode":"closed"},"accounts":{"domain":"accounts.example.test"}}`)
		_, err := svc.MergeAccounts(closed, survivor.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", false)
		require.ErrorIs(t, err, ErrAccessNotAllowed)
	})
	t.Run("deactivated account", func(t *testing.T) {
		svc, _, survivor, native, ctx := mergeFixture(t)
		native.Status = StatusDeactivated
		_, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", false)
		require.Error(t, err)
	})
	t.Run("unverified email when verification is required", func(t *testing.T) {
		svc, repo, survivor, _, ctx := mergeFixture(t)
		svc.cfg.AuthRequireVerifiedEmail = true
		seedUser(repo, "eve@mail.example.com", hashPW(t, accessTestPassword), StatusActive)
		_, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "eve@mail.example.com", accessTestPassword, "203.0.113.10", "agent", false)
		require.ErrorIs(t, err, ErrEmailVerificationRequired)
	})
}

func TestMergeAccounts_MovesEmailAndLinkedCredentials(t *testing.T) {
	svc, repo, _, _, ctx := mergeFixture(t)
	// A username-only survivor absorbs an email account with a linked provider.
	survivor := seedUser(repo, "", hashPW(t, "An0ther!Passw0rd"), StatusActive)
	survivor.Username = "carol"
	other := verified(seedUser(repo, "carol@mail.example.com", hashPW(t, accessTestPassword), StatusActive))
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{UserID: other.ID, Provider: "google", ProviderUserID: "g-1"}))

	merged, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "carol@mail.example.com", accessTestPassword, "203.0.113.10", "agent", false)
	require.NoError(t, err)
	require.Equal(t, "carol@mail.example.com", merged.Email, "the survivor had no email: it takes the other's")
	linked, err := repo.FindUserByProviderID(ctx, "google", "g-1")
	require.NoError(t, err)
	require.Equal(t, survivor.ID, linked.ID, "the provider identity signs in to the survivor")
}

func TestMergeAccounts_ConcurrentChangeIsAConflict(t *testing.T) {
	repo := newFakeRepo()
	a := seedUser(repo, "a@mail.example.test", "", StatusActive)
	b := seedUser(repo, "b@mail.example.test", "", StatusActive)
	b.Status = StatusDeactivated // changed after the checks
	err := repo.ApplyAccountMerge(context.Background(), AccountMerge{SurvivorID: a.ID, OtherID: b.ID, AtMs: 1})
	require.ErrorIs(t, err, ErrMergeConflict)
}

// A caller whose own account could never be a survivor learns nothing about
// the other account's password: it is refused before any password check.
func TestMergeAccounts_SurvivorCheckedBeforeThePassword(t *testing.T) {
	svc, repo, survivor, native, ctx := mergeFixture(t)
	survivor.Status = StatusDeactivated
	_, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", "Wr0ng!Passw0rd", "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrMergeRefused)
	got, _ := repo.GetUser(ctx, native.ID)
	require.Zero(t, got.FailedLoginCount, "no password was checked")
}

// A merge is announced at every address either account had.
func TestMergeAccounts_NotifiesBothAddresses(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.AccountMergeEnabled = true
	ctx := accountsScope(t, "accounts.example.test")
	survivor := seedUser(repo, "keep@mail.example.com", "", StatusActive)
	verified(seedUser(repo, "gone@mail.example.com", hashPW(t, accessTestPassword), StatusActive))

	_, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "gone@mail.example.com", accessTestPassword, "203.0.113.4", "agent", false)
	require.NoError(t, err)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	to := map[string]bool{}
	for _, m := range rec.sent {
		if m.Subject == AccountMergedSubject {
			to[m.To] = true
		}
	}
	require.True(t, to["keep@mail.example.com"] && to["gone@mail.example.com"], "notices: %v", to)
}

// An account an identity provider manages is merged only by an admin.
func TestMergeAccounts_RefusesIdPManagedAccounts(t *testing.T) {
	svc, _, survivor, native, ctx := mergeFixture(t)
	native.ExternalID = "idp-7"
	_, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.4", "agent", false)
	require.ErrorIs(t, err, ErrMergeRefused)

	svc2, _, survivor2, _, ctx2 := mergeFixture(t)
	survivor2.ExternalID = "idp-8"
	_, err = svc2.MergeAccounts(ctx2, survivor2.ID, freshAuth(svc2), "bob", accessTestPassword, "203.0.113.4", "agent", false)
	require.ErrorIs(t, err, ErrMergeRefused)
}

func TestMergeUsers_RefusesTheAdminsOwnAccountAndKeepsTOTPPasswords(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@example.test", "Admin", "admin", "active")
	repo := newFakeRepo()
	svc := newTestAdminServiceWithRepo(db, repo)
	ctx := accountsScope(t, "accounts.example.test")

	_, err := svc.MergeUsers(ctx, "admin-1", "someone", "admin-1", false)
	require.ErrorIs(t, err, ErrMergeRefused)

	survivor := seedUser(repo, "a@mail.example.com", "", StatusActive)
	other := seedUser(repo, "", hashPW(t, accessTestPassword), StatusActive)
	other.Username = "tia"
	other.TotpRequired = true
	merged, err := svc.MergeUsers(ctx, "admin-1", survivor.ID, other.ID, false)
	require.NoError(t, err)
	require.Empty(t, merged.PasswordHash, "a password a second factor protected does not move")
	require.Equal(t, "tia", merged.Username)
}

// An invitation issued before a merge must not bring the retired account back.
func TestAcceptInvitation_RefusesAMergedAccount(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := context.Background()
	token := seedInvitedUser(t, repo, "invitee@example.com")
	invitee, err := repo.FindUserByEmail(ctx, "invitee@example.com")
	require.NoError(t, err)
	require.NoError(t, repo.UpdateUser(ctx, invitee.ID, map[string]any{
		"status": StatusDeactivated, "merged_into_user_id": "survivor-1",
	}))

	res, err := svc.AcceptInvitation(ctx, token, accessTestPassword, "Invitee", "203.0.113.10", "agent")
	require.ErrorIs(t, err, ErrMergeRefused)
	require.Nil(t, res, "no tokens for a merged account")
	still, _ := repo.GetUser(ctx, invitee.ID)
	require.Equal(t, StatusDeactivated, still.Status)
	require.Empty(t, still.PasswordHash, "the invitation set no password")
}

// freshAuth is a session signed in just now.
func freshAuth(svc *AuthService) int64 { return svc.nowMs() / 1000 }

// The account that is kept must have signed in recently: a session alone —
// stolen, or simply long-lived — cannot pull another account onto it.
func TestMergeAccounts_RequiresARecentSignIn(t *testing.T) {
	svc, repo, survivor, native, ctx := mergeFixture(t)
	maxAge := int64(svc.cfg.AccountMergeReauthMaxAge().Seconds())
	now := svc.nowMs() / 1000

	for name, authTime := range map[string]int64{
		"no sign-in time": 0,
		"too long ago":    now - maxAge - 1,
		"in the future":   now + 120,
	} {
		_, err := svc.MergeAccounts(ctx, survivor.ID, authTime, "bob", accessTestPassword, "203.0.113.10", "agent", false)
		require.ErrorIs(t, err, ErrReauthenticationRequired, name)
		require.Contains(t, err.Error(), "reauthentication_required")
	}
	// A refused merge looked at nothing: the other account's lockout counter
	// did not move on a wrong password.
	_, err := svc.MergeAccounts(ctx, survivor.ID, 0, "bob", "Wr0ng!Passw0rd", "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrReauthenticationRequired)
	still, _ := repo.GetUser(ctx, native.ID)
	require.Zero(t, still.FailedLoginCount)

	_, err = svc.MergeAccounts(ctx, survivor.ID, now-maxAge+5, "bob", accessTestPassword, "203.0.113.10", "agent", false)
	require.NoError(t, err, "a sign-in within the window is enough")
}

// auth_time is stamped by a sign-in, and a refresh — not a sign-in — carries
// none.
func TestTokens_AuthTimeIsTheSignIn(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	seedUser(repo, "signin@example.com", hashPW(t, strongPW), StatusActive)

	signedInAt := time.Now().Add(-time.Hour)
	svc.nowFunc = func() time.Time { return signedInAt }
	login, err := svc.PasswordLogin(ctx, "signin@example.com", strongPW, "203.0.113.10", "agent")
	require.NoError(t, err)
	claims, err := jwt.VerifyAccessToken(login.AccessToken, svc.signer, "", "", false)
	require.NoError(t, err)
	require.Equal(t, signedInAt.Unix(), claims.AuthTime)

	svc.nowFunc = time.Now
	_, access, _, err := svc.RefreshToken(ctx, login.RefreshToken, "203.0.113.10", "agent")
	require.NoError(t, err)
	claims, err = jwt.VerifyAccessToken(access, svc.signer, "", "", false)
	require.NoError(t, err)
	require.Zero(t, claims.AuthTime, "a refresh is not a sign-in")
}

// Two spellings of one Gmail mailbox reach one inbox, so the person gets one
// notice, not two.
func TestMergeAccounts_OneNoticeForTwoSpellingsOfOneMailbox(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.cfg.AccountMergeEnabled = true
	ctx := accountsScope(t, "accounts.example.test")
	survivor := seedUser(repo, "first.last@gmail.com", "", StatusActive)
	verified(seedUser(repo, "firstlast@gmail.com", hashPW(t, accessTestPassword), StatusActive))

	_, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "firstlast@gmail.com", accessTestPassword, "203.0.113.4", "agent", false)
	require.NoError(t, err)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	notices := 0
	for _, m := range rec.sent {
		if m.Subject == AccountMergedSubject {
			notices++
		}
	}
	require.Equal(t, 1, notices)
}
