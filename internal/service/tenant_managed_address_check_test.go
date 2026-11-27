package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
)

// addressCheckFixture is a managed-membership fixture whose tenant has
// maDomain verified and another domain only pending, its holders answered by
// holders.
func addressCheckFixture(t *testing.T, holders func(string, string, []string) (map[string]string, error)) (*membershipFixture, *fakeDomainStore) {
	t.Helper()
	f, _ := managedMembershipFixture(&managedSetupsMock{holders: holders})
	domains := newFakeDomainStore()
	f.svc.WithDomains(domains).WithManagedAddressCheckBudget(1000, 60_000)
	ctx := context.Background()
	for name, status := range map[string]string{maDomain: DomainStatusVerified, "pending.example.com": DomainStatusPending} {
		_, err := domains.CreateDomain(ctx, &Domain{ProjectID: mTestProject, TenantID: mTestTenant, Domain: name, VerificationMethod: DomainVerificationDNSTXT, Status: status})
		require.NoError(t, err)
	}
	return f, domains
}

func TestCheckManagedAddresses_AnswersEachAddressInOrder(t *testing.T) {
	var looked []string
	f, _ := addressCheckFixture(t, func(projectID, tenantID string, addresses []string) (map[string]string, error) {
		require.Equal(t, mTestProject, projectID)
		require.Equal(t, mTestTenant, tenantID)
		looked = addresses
		return map[string]string{
			"ann@" + maDomain:   ManagedAddressFree,
			"bob@" + maDomain:   ManagedAddressManagedByThis,
			"carol@" + maDomain: ManagedAddressHeldOutsideTheTenant,
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
	require.Equal(t, []string{"ann@" + maDomain, "bob@" + maDomain, "carol@" + maDomain}, looked,
		"only addresses on the tenant's verified domains are looked up")
}

func TestCheckManagedAddresses_ProjectRefusedAddressesAreInvalid(t *testing.T) {
	f, _ := addressCheckFixture(t, func(string, string, []string) (map[string]string, error) {
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
		mutate  func(*membershipFixture, *fakeDomainStore)
		want    error
	}{
		"no project":      {ctx: context.Background(), caller: mAdminID, tenant: mTestTenant, queries: one, want: ErrPermissionDenied},
		"no caller":       {caller: "", tenant: mTestTenant, queries: one, want: ErrUnauthenticated},
		"no tenant":       {caller: mAdminID, tenant: " ", queries: one, want: ErrInvalidArgument},
		"no addresses":    {caller: mAdminID, tenant: mTestTenant, want: ErrInvalidArgument},
		"too many":        {caller: mAdminID, tenant: mTestTenant, queries: tooMany, want: ErrInvalidArgument},
		"not an admin":    {caller: "stranger", tenant: mTestTenant, queries: one, want: ErrPermissionDenied},
		"another tenant":  {caller: mAdminID, tenant: "other-tenant", queries: one, want: ErrPermissionDenied},
		"not admitted":    {ctx: managedScope(ProjectAccessConfig{}), caller: mAdminID, tenant: mTestTenant, queries: one, want: ErrManagedAccountsNotAdmitted},
		"domains unread":  {caller: mAdminID, tenant: mTestTenant, queries: one, mutate: func(_ *membershipFixture, d *fakeDomainStore) { d.listErr = storeErr }, want: storeErr},
		"no domain store": {caller: mAdminID, tenant: mTestTenant, queries: one, mutate: func(f *membershipFixture, _ *fakeDomainStore) { f.svc.domains = nil }, want: ErrUnimplemented},
	} {
		t.Run(name, func(t *testing.T) {
			f, domains := addressCheckFixture(t, func(string, string, []string) (map[string]string, error) { return map[string]string{}, nil })
			if tc.mutate != nil {
				tc.mutate(f, domains)
			}
			ctx := tc.ctx
			if ctx == nil {
				ctx = managedScope(admitted())
			}
			_, err := f.svc.CheckManagedAddresses(ctx, tc.caller, tc.tenant, tc.queries)
			require.ErrorIs(t, err, tc.want)
		})
	}

	f, _ := addressCheckFixture(t, func(string, string, []string) (map[string]string, error) { return nil, storeErr })
	_, err := f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, one)
	require.ErrorIs(t, err, storeErr)

	plain := newMembershipFixtureWith(true, &config.Config{ManagedAccountsEnabled: true})
	plain.seedAdmin(mTestProject, mTestTenant, mAdminID)
	_, err = plain.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, one)
	require.ErrorIs(t, err, ErrUnimplemented, "without the managed store the check is unimplemented")
}

// The check is capped per tenant: past the budget every call is refused,
// whatever it asks, and other tenants keep theirs.
func TestCheckManagedAddresses_CappedPerTenant(t *testing.T) {
	f, _ := addressCheckFixture(t, func(string, string, []string) (map[string]string, error) { return map[string]string{}, nil })
	f.svc.WithManagedAddressCheckBudget(2, 60_000)
	f.seedAdmin(mTestProject, "tenant-2", mAdminID)
	one := []ManagedAddressQuery{{Username: "ann", Domain: maDomain}}
	for i := range 2 {
		_, err := f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, one)
		require.NoError(t, err, "call %d", i+1)
	}
	_, err := f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, one)
	require.ErrorIs(t, err, ErrManagedAddressCheckLimited)
	_, err = f.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, "tenant-2", one)
	require.NoError(t, err, "another tenant keeps its own budget")

	unbudgeted, _ := managedMembershipFixture(&managedSetupsMock{})
	unbudgeted.svc.WithDomains(newFakeDomainStore())
	_, err = unbudgeted.svc.CheckManagedAddresses(managedScope(admitted()), mAdminID, mTestTenant, one)
	require.ErrorIs(t, err, ErrUnimplemented, "the check never runs without its budget")
}
