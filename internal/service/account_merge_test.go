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

	merged, err := svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, true)
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

	merged, err := svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, false)
	require.NoError(t, err)
	require.Equal(t, "robert", merged.Username)
	require.Equal(t, "bob-at-mail.example.test@accounts.example.test", merged.AccountAddress)
	retired, _ := repo.GetUser(ctx, native.ID)
	require.Equal(t, "bob", retired.Username, "a username the survivor does not take stays on the retired account")
	require.Equal(t, "bob@accounts.example.test", retired.AccountAddress)
}

func TestMergeAccounts_ProofAndRefusals(t *testing.T) {
	svc, repo, survivor, native, ctx := mergeFixture(t)

	_, err := svc.MergeAccounts(ctx, survivor.ID, "bob", "Wr0ng!Passw0rd", false)
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = svc.MergeAccounts(ctx, survivor.ID, "nobody", accessTestPassword, false)
	require.ErrorIs(t, err, ErrUnauthenticated, "an unknown identifier gets the same refusal")
	_, err = svc.MergeAccounts(ctx, survivor.ID, "", "", false)
	require.ErrorIs(t, err, ErrInvalidArgument)

	native.TotpRequired = true
	_, err = svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, false)
	require.ErrorIs(t, err, ErrMergeRefused)
	native.TotpRequired = false

	// Into itself.
	_, err = svc.MergeAccounts(ctx, native.ID, "bob", accessTestPassword, false)
	require.ErrorIs(t, err, ErrMergeRefused)

	// A guardian's account is not merged away from its children.
	child := seedUser(repo, "", "", StatusActive)
	seedGuardianEdge(ctx, t, repo, native.ID, child.ID)
	_, err = svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, false)
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
	_, err := svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, false)
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

// failSecondUpdateRepo fails the second UpdateUser call: the write to the
// survivor, after the other account was retired.
type failSecondUpdateRepo struct {
	*fakeRepo
	calls int
}

func (r *failSecondUpdateRepo) WithProject(string) Repository { return r }

func (r *failSecondUpdateRepo) UpdateUser(ctx context.Context, id string, f map[string]any) error {
	r.calls++
	if r.calls == 2 {
		return context.DeadlineExceeded
	}
	return r.fakeRepo.UpdateUser(ctx, id, f)
}

func TestMergeAccounts_FailedSurvivorWriteRestoresTheOther(t *testing.T) {
	inner := newFakeRepo()
	survivor := seedUser(inner, "bob@mail.example.test", "", StatusActive)
	native := seedUser(inner, "", "hash", StatusActive)
	native.Username = "bob"
	repo := &failSecondUpdateRepo{fakeRepo: inner}
	_, _, err := mergeAccounts(context.Background(), repo, survivor, native, false, 1)
	require.Error(t, err)
	got, _ := inner.GetUser(context.Background(), native.ID)
	require.Equal(t, StatusActive, got.Status)
	require.Equal(t, "bob", got.Username)
	require.Empty(t, got.MergedIntoUserID)
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
