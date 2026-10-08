package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
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

	merged, err := svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, "1.2.3.4", "agent", true)
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
	login, err := svc.PasswordLogin(ctx, "bob", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.Equal(t, survivor.ID, login.User.ID)
}

func TestMergeAccounts_KeepsTheSurvivorsOwnWhenItHasThem(t *testing.T) {
	svc, repo, survivor, native, ctx := mergeFixture(t)
	survivor.Username = "robert"
	survivor.PasswordHash = hashPW(t, "An0ther!Passw0rd")

	merged, err := svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, "1.2.3.4", "agent", false)
	require.NoError(t, err)
	require.Equal(t, "robert", merged.Username)
	require.Equal(t, "bob-at-mail.example.test@accounts.example.test", merged.AccountAddress)
	retired, _ := repo.GetUser(ctx, native.ID)
	require.Equal(t, "bob", retired.Username, "a username the survivor does not take stays on the retired account")
	require.Equal(t, "bob@accounts.example.test", retired.AccountAddress)
}

func TestMergeAccounts_ProofAndRefusals(t *testing.T) {
	svc, repo, survivor, native, ctx := mergeFixture(t)

	_, err := svc.MergeAccounts(ctx, survivor.ID, "bob", "Wr0ng!Passw0rd", "1.2.3.4", "agent", false)
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = svc.MergeAccounts(ctx, survivor.ID, "nobody", accessTestPassword, "1.2.3.4", "agent", false)
	require.ErrorIs(t, err, ErrUnauthenticated, "an unknown identifier gets the same refusal")
	_, err = svc.MergeAccounts(ctx, survivor.ID, "", "", "1.2.3.4", "agent", false)
	require.Error(t, err)

	native.TotpRequired = true
	_, err = svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, "1.2.3.4", "agent", false)
	require.ErrorIs(t, err, ErrMergeRefused)
	native.TotpRequired = false

	// Into itself.
	_, err = svc.MergeAccounts(ctx, native.ID, "bob", accessTestPassword, "1.2.3.4", "agent", false)
	require.ErrorIs(t, err, ErrMergeRefused)

	// A guardian's account is not merged away from its children.
	child := seedUser(repo, "", "", StatusActive)
	seedGuardianEdge(ctx, t, repo, native.ID, child.ID)
	_, err = svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, "1.2.3.4", "agent", false)
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
	_, err := svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, "1.2.3.4", "agent", false)
	require.NoError(t, err)
	_, err = svc.PasswordLogin(ctx, "bob", accessTestPassword, "1.2.3.4", "agent")
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
	_, err := svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, "1.2.3.4", "agent", false)
	require.ErrorIs(t, err, ErrAccountMergeDisabled)
}

// The proof is the whole password sign-in check, so an account a sign-in
// would refuse cannot be merged either.
func TestMergeAccounts_UsesTheSignInGates(t *testing.T) {
	t.Run("closed project", func(t *testing.T) {
		svc, _, survivor, _, _ := mergeFixture(t)
		closed := signupScope(t, `{"access":{"mode":"closed"},"accounts":{"domain":"accounts.example.test"}}`)
		_, err := svc.MergeAccounts(closed, survivor.ID, "bob", accessTestPassword, "1.2.3.4", "agent", false)
		require.ErrorIs(t, err, ErrAccessNotAllowed)
	})
	t.Run("deactivated account", func(t *testing.T) {
		svc, _, survivor, native, ctx := mergeFixture(t)
		native.Status = StatusDeactivated
		_, err := svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, "1.2.3.4", "agent", false)
		require.Error(t, err)
	})
	t.Run("unverified email when verification is required", func(t *testing.T) {
		svc, repo, survivor, _, ctx := mergeFixture(t)
		svc.cfg.AuthRequireVerifiedEmail = true
		seedUser(repo, "eve@mail.example.com", hashPW(t, accessTestPassword), StatusActive)
		_, err := svc.MergeAccounts(ctx, survivor.ID, "eve@mail.example.com", accessTestPassword, "1.2.3.4", "agent", false)
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

	merged, err := svc.MergeAccounts(ctx, survivor.ID, "carol@mail.example.com", accessTestPassword, "1.2.3.4", "agent", false)
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
