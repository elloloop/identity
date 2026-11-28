package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// projectMembersFixture is a project store beside two console accounts:
// owner, who creates projects, and stranger, who belongs to none.
type projectMembersFixture struct {
	store           *ProjectStore
	owner, stranger string
}

func newProjectMembersFixture(ctx context.Context, t *testing.T) *projectMembersFixture {
	t.Helper()
	join := newJoinFixture(ctx, t, memberRoleDSN(t))
	return &projectMembersFixture{
		store:    NewProjectStore(join.accounts, false, nil),
		owner:    join.user,
		stranger: join.other,
	}
}

func (f *projectMembersFixture) request(name, key string, maxOwned int) service.OwnedProjectRequest {
	return service.OwnedProjectRequest{Name: name, OwnerID: f.owner, MaxOwned: maxOwned, PublishableKey: key}
}

// TestProjectStore_CreateOwnedProject_CreatesProjectOwnerAndKey: one call
// leaves a project that is its own storage scope, with an empty config, its
// creator as owner and a publishable credential that resolves to it.
func TestProjectStore_CreateOwnedProject_CreatesProjectOwnerAndKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newProjectMembersFixture(ctx, t)
	const nowMs = int64(1_700_000_000_000)

	req := f.request("Acme Storefront", "pk_acme_storefront", 5)
	req.NowMs = nowMs
	created, err := f.store.CreateOwnedProject(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "Acme Storefront", created.Name)
	assert.Equal(t, service.ProjectRoleOwner, created.Role)
	assert.Equal(t, "pk_acme_storefront", created.PublishableKey)
	assert.Equal(t, nowMs, created.CreatedAtMs)

	seen, err := f.store.GetMemberProject(ctx, created.ID, f.owner)
	require.NoError(t, err)
	require.NotNil(t, seen)
	assert.Equal(t, created, seen)

	config, version, err := f.store.GetProjectConfig(ctx, created.ID)
	require.NoError(t, err)
	assert.JSONEq(t, "{}", config, "a new project has no config, so no access mode: it admits nobody yet")
	assert.Zero(t, version)

	var scope string
	require.NoError(t, f.store.pool.QueryRow(ctx, `SELECT storage_scope_id FROM projects WHERE id = $1`, created.ID).Scan(&scope))
	assert.Equal(t, created.ID, scope, "a self-service project is its own storage scope")

	credential, err := f.store.GetProjectCredentialByPublicID(ctx, "pk_acme_storefront")
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, created.ID, credential.ProjectID)
	assert.Equal(t, service.CredentialKindPublishable, credential.Kind)
	assert.Empty(t, credential.SecretHash, "a publishable key has no secret half")
}

// TestProjectStore_CreateOwnedProject_Limit: an owner at the limit is
// refused and nothing is left behind, and projects the account does not own
// do not count against it.
func TestProjectStore_CreateOwnedProject_Limit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newProjectMembersFixture(ctx, t)

	_, err := f.store.CreateOwnedProject(ctx, f.request("One", "pk_one", 2))
	require.NoError(t, err)
	_, err = f.store.CreateOwnedProject(ctx, f.request("Two", "pk_two", 2))
	require.NoError(t, err)

	_, err = f.store.CreateOwnedProject(ctx, f.request("Three", "pk_three", 2))
	require.ErrorIs(t, err, service.ErrProjectCreationLimited)
	leftover, err := f.store.GetProjectCredentialByPublicID(ctx, "pk_three")
	require.NoError(t, err)
	assert.Nil(t, leftover, "a refused creation leaves no credential")
	projects, err := f.store.ListMemberProjects(ctx, f.owner)
	require.NoError(t, err)
	assert.Len(t, projects, 2)

	other := service.OwnedProjectRequest{Name: "Theirs", OwnerID: f.stranger, MaxOwned: 1, PublishableKey: "pk_theirs"}
	_, err = f.store.CreateOwnedProject(ctx, other)
	require.NoError(t, err, "another account's limit is its own")
}

// TestProjectStore_CreateOwnedProject_LimitHoldsUnderConcurrency: requests
// racing for the last place under the limit are serialized, so exactly one
// wins.
func TestProjectStore_CreateOwnedProject_LimitHoldsUnderConcurrency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newProjectMembersFixture(ctx, t)
	const attempts = 8

	var wg sync.WaitGroup
	errs := make([]error, attempts)
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = f.store.CreateOwnedProject(ctx, f.request("Racer", fmt.Sprintf("pk_racer_%d", i), 1))
		}()
	}
	wg.Wait()

	var created, limited int
	for _, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, service.ErrProjectCreationLimited):
			limited++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	assert.Equal(t, 1, created, "exactly one request fits under a limit of one")
	assert.Equal(t, attempts-1, limited)
}

// TestProjectStore_CreateOwnedProject_RefusesIncompleteRequests: the store
// does not create a project nobody owns or no application could select.
func TestProjectStore_CreateOwnedProject_RefusesIncompleteRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newProjectMembersFixture(ctx, t)

	for name, req := range map[string]service.OwnedProjectRequest{
		"no owner": {Name: "Acme", MaxOwned: 1, PublishableKey: "pk_a"},
		"no name":  {OwnerID: f.owner, MaxOwned: 1, PublishableKey: "pk_a"},
		"no key":   {Name: "Acme", OwnerID: f.owner, MaxOwned: 1},
		"no limit": {Name: "Acme", OwnerID: f.owner, PublishableKey: "pk_a"},
	} {
		_, err := f.store.CreateOwnedProject(ctx, req)
		assert.ErrorIs(t, err, service.ErrInvalidArgument, name)
	}
}

// TestProjectStore_MemberProjects_AreTheMembersOwn: a project is listed for,
// and readable by, its members only; a non-member, an unknown project and a
// suspended one all read as nothing.
func TestProjectStore_MemberProjects_AreTheMembersOwn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newProjectMembersFixture(ctx, t)

	first := f.request("First", "pk_first", 5)
	first.NowMs = 1_700_000_000_000
	older, err := f.store.CreateOwnedProject(ctx, first)
	require.NoError(t, err)
	second := f.request("Second", "pk_second", 5)
	second.NowMs = 1_700_000_100_000
	newer, err := f.store.CreateOwnedProject(ctx, second)
	require.NoError(t, err)

	projects, err := f.store.ListMemberProjects(ctx, f.owner)
	require.NoError(t, err)
	require.Len(t, projects, 2)
	assert.Equal(t, []string{older.ID, newer.ID}, []string{projects[0].ID, projects[1].ID}, "oldest first")

	none, err := f.store.ListMemberProjects(ctx, f.stranger)
	require.NoError(t, err)
	assert.Empty(t, none)
	for name, lookup := range map[string][2]string{
		"non-member":      {older.ID, f.stranger},
		"unknown project": {"project-missing", f.owner},
	} {
		got, err := f.store.GetMemberProject(ctx, lookup[0], lookup[1])
		require.NoError(t, err, name)
		assert.Nil(t, got, name)
	}

	_, err = f.store.pool.Exec(ctx, `UPDATE projects SET status = 'suspended' WHERE id = $1`, older.ID)
	require.NoError(t, err)
	suspended, err := f.store.GetMemberProject(ctx, older.ID, f.owner)
	require.NoError(t, err)
	assert.Nil(t, suspended, "a suspended project serves nothing, its console included")
	projects, err = f.store.ListMemberProjects(ctx, f.owner)
	require.NoError(t, err)
	require.Len(t, projects, 1)
	assert.Equal(t, newer.ID, projects[0].ID)

	_, err = f.store.CreateOwnedProject(ctx, f.request("Third", "pk_third", 2))
	require.ErrorIs(t, err, service.ErrProjectCreationLimited, "a suspended project still counts against its owner's limit")
}

// TestProjectStore_MemberProject_ShowsTheOldestActivePublishableKey: a
// revoked key is not shown, and with none active the project shows none.
func TestProjectStore_MemberProject_ShowsTheOldestActivePublishableKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newProjectMembersFixture(ctx, t)

	req := f.request("Acme", "pk_first", 5)
	req.NowMs = 1_700_000_000_000
	project, err := f.store.CreateOwnedProject(ctx, req)
	require.NoError(t, err)
	_, err = f.store.createProjectCredential(ctx, &ProjectCredential{
		ProjectID: project.ID, Kind: service.CredentialKindPublishable, PublicID: "pk_second", CreatedAtMs: 1_700_000_100_000,
	})
	require.NoError(t, err)
	_, err = f.store.createProjectCredential(ctx, &ProjectCredential{
		ProjectID: project.ID, Kind: service.CredentialKindSecret, PublicID: "sk_older", SecretHash: "hash", CreatedAtMs: 1_600_000_000_000,
	})
	require.NoError(t, err)

	shown := func() string {
		t.Helper()
		p, err := f.store.GetMemberProject(ctx, project.ID, f.owner)
		require.NoError(t, err)
		require.NotNil(t, p)
		return p.PublishableKey
	}
	assert.Equal(t, "pk_first", shown(), "the oldest publishable key, never a secret one")

	revoke := func(publicID string) {
		t.Helper()
		_, err := f.store.pool.Exec(ctx, `UPDATE project_credentials SET status = 'revoked' WHERE public_id = $1`, publicID)
		require.NoError(t, err)
	}
	revoke("pk_first")
	assert.Equal(t, "pk_second", shown())
	revoke("pk_second")
	assert.Empty(t, shown())
}

// TestProjectStore_ProjectMembers_GoWithTheProjectAndTheAccount: a
// membership does not outlive the project or the account it names.
func TestProjectStore_ProjectMembers_GoWithTheProjectAndTheAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newProjectMembersFixture(ctx, t)

	count := func() int {
		t.Helper()
		var n int
		require.NoError(t, f.store.pool.QueryRow(ctx, `SELECT count(*) FROM project_members`).Scan(&n))
		return n
	}
	gone, err := f.store.CreateOwnedProject(ctx, f.request("Gone", "pk_gone", 5))
	require.NoError(t, err)
	_, err = f.store.CreateOwnedProject(ctx, f.request("Kept", "pk_kept", 5))
	require.NoError(t, err)
	require.Equal(t, 2, count())

	_, err = f.store.pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, gone.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count(), "deleting a project deletes its memberships")

	_, err = f.store.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, f.owner)
	require.NoError(t, err)
	assert.Zero(t, count(), "deleting an account deletes its memberships")
}
