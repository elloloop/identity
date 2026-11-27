package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
)

// addressCheckFixture is a managed-membership fixture whose holders are
// answered by holders.
func addressCheckFixture(t *testing.T, holders func(string, string, []string) (map[string]string, error)) *membershipFixture {
	t.Helper()
	f, _ := managedMembershipFixture(&managedSetupsMock{holders: holders})
	f.svc.WithManagedAddressCheckBudget(1000, 60_000)
	return f
}

func TestCheckManagedAddresses_AnswersEachAddressInOrder(t *testing.T) {
	var looked []string
	f := addressCheckFixture(t, func(projectID, tenantID string, addresses []string) (map[string]string, error) {
		require.Equal(t, mTestProject, projectID)
		require.Equal(t, mTestTenant, tenantID)
		looked = addresses
		return map[string]string{
			"ann@" + maDomain:            ManagedAddressFree,
			"bob@" + maDomain:            ManagedAddressManagedByThis,
			"carol@" + maDomain:          ManagedAddressHeldOutsideTheTenant,
			"dan@pending.example.com":    ManagedAddressDomainUnverified,
			"erin@elsewhere.example.com": ManagedAddressDomainUnverified,
		}, nil
	})
	queries := []ManagedAddressQuery{
		{Username: "Ann", Domain: maDomain},
		{Username: "bob", Domain: strings.ToUpper(maDomain)},
		{Username: "carol", Domain: maDomain},
		{Username: "dan", Domain: "pending.example.com"},
		{Username: "erin", Domain: "elsewhere.example.com"},
		{Username: "fi..x", Domain: maDomain},
		{Username: "gus", Domain: ""},
	}
	got, err := f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, " "+mTestTenant+" ", queries)
	require.NoError(t, err)
	statuses := make([]string, len(got))
	for i, c := range got {
		require.Equal(t, queries[i], c.Query, "answers keep the asked order and spelling")
		statuses[i] = c.Status
	}
	require.Equal(t, []string{
		ManagedAddressFree, ManagedAddressManagedByThis, ManagedAddressHeldOutsideTheTenant,
		ManagedAddressDomainUnverified, ManagedAddressDomainUnverified, ManagedAddressInvalid, ManagedAddressInvalid,
	}, statuses)
	require.Equal(t, []string{"ann@" + maDomain, "bob@" + maDomain, "carol@" + maDomain, "dan@pending.example.com", "erin@elsewhere.example.com"}, looked,
		"every valid address goes to the store, which looks up only the tenant's verified domains")
}

func TestCheckManagedAddresses_ProjectRefusedAddressesAreInvalid(t *testing.T) {
	f := addressCheckFixture(t, func(string, string, []string) (map[string]string, error) {
		t.Fatal("nothing the project refuses is looked up")
		return nil, nil
	})
	access := ProjectAccessConfig{Mode: AccessModeOpen, AdmitManagedAccounts: true, BlockedDomains: []string{maDomain}}
	got, err := f.svc.CheckManagedAddresses(managedScope(access), mAdminID, mTestTenant, []ManagedAddressQuery{{Username: "ann", Domain: maDomain}})
	require.NoError(t, err)
	require.Equal(t, ManagedAddressInvalid, got[0].Status)

	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: mTestProject, Access: admitted(), Accounts: ProjectAccountsConfig{Domain: maDomain}})
	got, err = f.svc.CheckManagedAddresses(ctx, mAdminID, mTestTenant, []ManagedAddressQuery{{Username: "ann", Domain: maDomain}})
	require.NoError(t, err)
	require.Equal(t, ManagedAddressInvalid, got[0].Status)
}

func TestCheckManagedAddresses_Refusals(t *testing.T) {
	storeErr := errors.New("db down")
	one := []ManagedAddressQuery{{Username: "ann", Domain: maDomain}}
	tooMany := make([]ManagedAddressQuery, maxManagedAddressChecks+1)
	for name, tc := range map[string]struct {
		ctx     context.Context
		caller  string
		tenant  string
		queries []ManagedAddressQuery
		mutate  func(*membershipFixture)
		want    error
	}{
		"no project":     {ctx: context.Background(), caller: mAdminID, tenant: mTestTenant, queries: one, want: ErrPermissionDenied},
		"no caller":      {caller: "", tenant: mTestTenant, queries: one, want: ErrUnauthenticated},
		"no tenant":      {caller: mAdminID, tenant: " ", queries: one, want: ErrInvalidArgument},
		"no addresses":   {caller: mAdminID, tenant: mTestTenant, want: ErrInvalidArgument},
		"too many":       {caller: mAdminID, tenant: mTestTenant, queries: tooMany, want: ErrInvalidArgument},
		"not an admin":   {caller: "stranger", tenant: mTestTenant, queries: one, want: ErrPermissionDenied},
		"another tenant": {caller: mAdminID, tenant: "other-tenant", queries: one, want: ErrPermissionDenied},
		"not admitted":   {ctx: managedScope(ProjectAccessConfig{}), caller: mAdminID, tenant: mTestTenant, queries: one, want: ErrManagedAccountsNotAdmitted},
		"suspended tenant": {caller: mAdminID, tenant: mTestTenant, queries: one, mutate: func(f *membershipFixture) {
			f.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Status: TenantStatusSuspended})
		}, want: ErrPermissionDenied},
		"suspended admin": {caller: "admin-2", tenant: mTestTenant, queries: one, mutate: func(f *membershipFixture) {
			_, _ = f.memberships.UpsertMembership(context.Background(), &TenantMembership{
				ProjectID: mTestProject, TenantID: mTestTenant, UserID: "admin-2",
				Source: MembershipSourceAdded, Role: RoleAdmin, Status: MembershipStatusSuspended,
			})
		}, want: ErrPermissionDenied},
	} {
		t.Run(name, func(t *testing.T) {
			f := addressCheckFixture(t, func(string, string, []string) (map[string]string, error) { return map[string]string{}, nil })
			if tc.mutate != nil {
				tc.mutate(f)
			}
			ctx := tc.ctx
			if ctx == nil {
				ctx = managedScope(admitted())
			}
			_, err := f.svc.CheckManagedAddresses(ctx, tc.caller, tc.tenant, tc.queries)
			require.ErrorIs(t, err, tc.want)
		})
	}

	f := addressCheckFixture(t, func(string, string, []string) (map[string]string, error) { return nil, storeErr })
	_, err := f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, one)
	require.ErrorIs(t, err, storeErr)

	plain := newMembershipFixtureWith(true, &config.Config{ManagedAccountsEnabled: true})
	plain.svc.WithManagedSetups(&managedSetupsMock{})
	plain.seedAdmin(mTestProject, mTestTenant, mAdminID)
	_, err = plain.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, one)
	require.ErrorIs(t, err, ErrUnimplemented, "without its budget the check is unimplemented")
}

// The tenant's budget counts the addresses looked up: a call spends one unit
// per address, refused whole once fewer are left, while an address nothing
// is looked up for costs nothing; other tenants keep their own budgets.
func TestCheckManagedAddresses_CappedPerTenant(t *testing.T) {
	f := addressCheckFixture(t, func(string, string, []string) (map[string]string, error) { return map[string]string{}, nil })
	f.svc.WithManagedAddressCheckBudget(3, 60_000)
	f.seedAdmin(mTestProject, "tenant-2", mAdminID)
	two := []ManagedAddressQuery{{Username: "ann", Domain: maDomain}, {Username: "bob", Domain: maDomain}}
	_, err := f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, two)
	require.NoError(t, err, "two of three units")
	_, err = f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, two)
	require.ErrorIs(t, err, ErrManagedAddressCheckLimited, "two more do not fit in the one left")
	_, err = f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, []ManagedAddressQuery{{Username: "x..y", Domain: maDomain}})
	require.NoError(t, err, "an address nothing is looked up for costs nothing")
	_, err = f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, two[:1])
	require.NoError(t, err, "the last unit")
	_, err = f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, "tenant-2", two)
	require.NoError(t, err, "another tenant keeps its own budget")

	unbudgeted, _ := managedMembershipFixture(&managedSetupsMock{})
	_, err = unbudgeted.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, two)
	require.ErrorIs(t, err, ErrUnimplemented, "the check never runs without its budget")
}
