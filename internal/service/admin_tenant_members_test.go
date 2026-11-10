package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/audit"
)

// A key adds a person of its project as an active member, recorded as its
// own with the operator's client; the admin secret does the same with no
// actor.
func TestAdminAddTenantMember_AddsAnActiveMember(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	f.users.set("proj", &User{ID: "newcomer", Email: "n@example.test", Status: StatusActive, EmailVerified: true})

	m, err := f.svc.AdminAddTenantMember(ctx, asTenantOperator(f.key.RawKey), "proj", "t-2", "aide", testOperatorIP, testOperatorUA)
	require.NoError(t, err)
	assert.Equal(t, RoleMember, m.Role)
	assert.Equal(t, MembershipSourceAdded, m.Source)
	assert.Equal(t, MembershipStatusActive, m.Status)
	_, err = f.svc.AdminAddTenantMember(ctx, asAdmin(testAdminSecret), "proj", "t-2", "newcomer", "", "")
	require.NoError(t, err)

	records := f.records.byEvent(string(audit.EventTenantMemberAdded))
	require.Len(t, records, 2)
	assert.Equal(t, projectAuditEntry{
		project: "proj", event: string(audit.EventTenantMemberAdded), actor: f.actor(),
		client:  [2]string{testOperatorIP, testOperatorUA},
		details: map[string]any{"project_id": "proj", "tenant_id": "t-2", "role": RoleMember},
	}, records[0])
	assert.Empty(t, records[1].actor, "the admin secret names no actor")
}

// A person who already holds an active membership keeps it, whatever its
// role and source: the call returns it and records nothing, so it never
// lowers a role and a retry is safe.
func TestAdminAddTenantMember_KeepsAnActiveMembership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	f.users.set("proj", &User{ID: "boss", Email: "b@example.test", Status: StatusActive, EmailVerified: true})
	f.seedMembership("boss", MembershipSourceCreated, RoleOwner, MembershipStatusActive)
	key := asTenantOperator(f.key.RawKey)

	for _, tc := range []struct{ user, role, source string }{
		{"boss", RoleOwner, MembershipSourceCreated},
		{"heir", RoleMember, MembershipSourceDomain},
	} {
		m, err := f.svc.AdminAddTenantMember(ctx, key, "proj", "t-1", tc.user, "", "")
		require.NoError(t, err, tc.user)
		assert.Equal(t, tc.role, m.Role, tc.user)
		assert.Equal(t, tc.source, m.Source, tc.user)
		stored, _ := f.members.GetMembership(ctx, "proj", "t-1", tc.user)
		assert.Equal(t, tc.role, stored.Role, tc.user)
		assert.Equal(t, tc.source, stored.Source, tc.user)
	}

	first, err := f.svc.AdminAddTenantMember(ctx, key, "proj", "t-2", "aide", "", "")
	require.NoError(t, err)
	again, err := f.svc.AdminAddTenantMember(ctx, key, "proj", "t-2", "aide", "", "")
	require.NoError(t, err)
	assert.Equal(t, first.ID, again.ID)
	assert.Len(t, f.records.byEvent(string(audit.EventTenantMemberAdded)), 1, "only the first addition is recorded")
}

// A membership that has ended becomes an active member one, its earlier
// role not restored with it.
func TestAdminAddTenantMember_RenewsAnEndedMembership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	f.seedMembership("aide", MembershipSourceDomain, RoleAdmin, MembershipStatusInactive)

	m, err := f.svc.AdminAddTenantMember(ctx, asTenantOperator(f.key.RawKey), "proj", "t-1", "aide", "", "")
	require.NoError(t, err)
	assert.Equal(t, RoleMember, m.Role)
	assert.Equal(t, MembershipSourceAdded, m.Source)
	assert.Equal(t, MembershipStatusActive, m.Status)
	assert.Len(t, f.records.byEvent(string(audit.EventTenantMemberAdded)), 1)
}

// The operator does not override the tenant's owners and admins: a person
// they suspended or removed is refused, and the membership or removal stands.
func TestAdminAddTenantMember_RefusesWhomTheTenantShutOut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	f.seedMembership("heir", MembershipSourceInvited, RoleMember, MembershipStatusSuspended)
	f.seedMembership("aide", MembershipSourceInvited, RoleMember, MembershipStatusActive)
	_, err := f.members.RemoveMembership(ctx, "proj", "t-1", "aide")
	require.NoError(t, err)

	for _, caller := range []OperatorCredentials{asTenantOperator(f.key.RawKey), asAdmin(testAdminSecret)} {
		for _, user := range []string{"heir", "aide"} {
			_, err := f.svc.AdminAddTenantMember(ctx, caller, "proj", "t-1", user, "", "")
			require.ErrorIs(t, err, ErrMemberRefusedByTenant, user)
		}
	}
	heir, _ := f.members.GetMembership(ctx, "proj", "t-1", "heir")
	assert.Equal(t, MembershipStatusSuspended, heir.Status)
	removed, _ := f.members.IsRemoved(ctx, "proj", "t-1", "aide")
	assert.True(t, removed, "the removal stands")
	aide, _ := f.members.GetMembership(ctx, "proj", "t-1", "aide")
	assert.Nil(t, aide)
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantMemberAdded)))
}

// Only an active, signed-up person with a verified email of the project, on
// a tenant of the project that has been governed, is added.
func TestAdminAddTenantMember_RefusesWhatItMayNotAdd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	f.users.set("proj", &User{ID: "unverified", Email: "u@example.test", Status: StatusActive})
	f.users.set("proj", &User{ID: "anon", IsAnonymous: true, Status: StatusActive, EmailVerified: true})
	f.users.set("proj", &User{ID: "bot", Kind: UserKindAgent, OwnerUserID: "heir", Status: StatusActive, EmailVerified: true})
	f.users.set("other", &User{ID: "outsider", Email: "o@example.test", Status: StatusActive, EmailVerified: true})
	f.tenants.put(&Tenant{ID: "t-latent", ProjectID: "proj", Status: TenantStatusLatent})
	f.tenants.put(&Tenant{ID: "t-other", ProjectID: "other", Status: TenantStatusClaimed})

	for name, tc := range map[string]struct {
		tenant, user string
		want         error
	}{
		"an unverified email":       {"t-2", "unverified", ErrIneligibleTenantMember},
		"an anonymous account":      {"t-2", "anon", ErrIneligibleTenantMember},
		"an agent":                  {"t-2", "bot", ErrIneligibleTenantMember},
		"a deactivated account":     {"t-2", "gone", ErrIneligibleTenantMember},
		"a latent tenant":           {"t-latent", "aide", ErrTenantStatusConflict},
		"another project's tenant":  {"t-other", "aide", ErrNotFound},
		"another project's account": {"t-2", "outsider", ErrNotFound},
		"no such account":           {"t-2", "nobody", ErrNotFound},
		"a blank user":              {"t-2", " ", ErrInvalidArgument},
	} {
		_, err := f.svc.AdminAddTenantMember(ctx, asTenantOperator(f.key.RawKey), "proj", tc.tenant, tc.user, "", "")
		require.ErrorIs(t, err, tc.want, name)
	}
	f.requireNothingCreated(t, 4)
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantMemberAdded)))
}

// A failed write is the store's error, and nothing is recorded.
func TestAdminAddTenantMember_StoreError(t *testing.T) {
	t.Parallel()
	f := newTenantOperatorFixture(t, testAdminSecret)
	boom := errors.New("write failed")
	f.members.upsertErr = boom
	_, err := f.svc.AdminAddTenantMember(context.Background(), asTenantOperator(f.key.RawKey), "proj", "t-2", "aide", "", "")
	require.ErrorIs(t, err, boom)
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantMemberAdded)))
}

// A tenant records what authorized its creation, and a key restores a
// suspended tenant a key created though nobody governs it. The admin secret,
// and a key on a tenant the secret or no operator created, keep the old
// refusal.
func TestAdminRestoreTenant_AKeyRestoresTheTenantsKeysCreated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	key := asTenantOperator(f.key.RawKey)
	byKey, err := f.svc.AdminCreateTenant(ctx, key, "proj", "Made by a key", "", "", "")
	require.NoError(t, err)
	bySecret, err := f.svc.AdminCreateTenant(ctx, asAdmin(testAdminSecret), "proj", "Made by the secret", "", "", "")
	require.NoError(t, err)
	stored, _ := f.tenants.GetTenant(ctx, "proj", byKey)
	assert.Equal(t, CredentialKindTenantOperator, stored.CreatorCredentialKind)
	stored, _ = f.tenants.GetTenant(ctx, "proj", bySecret)
	assert.Equal(t, CreatorAdminSecret, stored.CreatorCredentialKind)
	f.tenants.put(&Tenant{ID: "t-unmarked", ProjectID: "proj", Status: TenantStatusSuspended})
	for _, id := range []string{byKey, bySecret} {
		_, err := f.svc.AdminSuspendTenant(ctx, key, "proj", id, "hold", "", "")
		require.NoError(t, err)
	}

	_, err = f.svc.AdminRestoreTenant(ctx, asAdmin(testAdminSecret), "proj", byKey, "lifted", "", "")
	require.ErrorIs(t, err, ErrTenantStatusConflict, "the admin secret's rule is unchanged")
	for _, id := range []string{bySecret, "t-unmarked"} {
		_, err := f.svc.AdminRestoreTenant(ctx, key, "proj", id, "lifted", "", "")
		require.ErrorIs(t, err, ErrTenantStatusConflict, id)
	}

	restored, err := f.svc.AdminRestoreTenant(ctx, key, "proj", byKey, "lifted", testOperatorIP, testOperatorUA)
	require.NoError(t, err)
	assert.Equal(t, TenantStatusClaimed, restored.Status)
	records := f.records.byEvent(string(audit.EventTenantRestored))
	require.Len(t, records, 1)
	assert.Equal(t, f.actor(), records[0].actor)
	assert.Equal(t, map[string]any{"project_id": "proj", "tenant_id": byKey, "reason": "lifted"}, records[0].details)
}
