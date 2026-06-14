package service

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
)

// ── Fakes ──────────────────────────────────────────────────────────────

// fakeDomainStore is an in-memory DomainStore keyed by (projectID, id).
type fakeDomainStore struct {
	byID      map[string]*Domain
	createErr error
	getErr    error
	setErr    error
	listErr   error
	nextID    int
}

func newFakeDomainStore() *fakeDomainStore {
	return &fakeDomainStore{byID: map[string]*Domain{}}
}

func (f *fakeDomainStore) key(projectID, id string) string { return projectID + "/" + id }

func (f *fakeDomainStore) CreateDomain(_ context.Context, d *Domain) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	f.nextID++
	id := d.ID
	if id == "" {
		id = "dom-" + strconv.Itoa(f.nextID)
	}
	stored := *d
	stored.ID = id
	f.byID[f.key(d.ProjectID, id)] = &stored
	return id, nil
}

func (f *fakeDomainStore) GetDomain(_ context.Context, projectID, domainID string) (*Domain, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	d, ok := f.byID[f.key(projectID, domainID)]
	if !ok {
		return nil, nil
	}
	out := *d
	return &out, nil
}

func (f *fakeDomainStore) GetDomainByName(_ context.Context, projectID, domain string) (*Domain, error) {
	for _, d := range f.byID {
		if d.ProjectID == projectID && d.Domain == domain {
			out := *d
			return &out, nil
		}
	}
	return nil, nil
}

func (f *fakeDomainStore) SetDomainStatus(_ context.Context, projectID, domainID, status string, verifiedAtMs int64) error {
	if f.setErr != nil {
		return f.setErr
	}
	d, ok := f.byID[f.key(projectID, domainID)]
	if !ok {
		return nil
	}
	d.Status = status
	if status == DomainStatusVerified {
		if verifiedAtMs == 0 {
			verifiedAtMs = 1
		}
		d.VerifiedAtMs = verifiedAtMs
	}
	return nil
}

func (f *fakeDomainStore) ListDomainsByTenant(_ context.Context, projectID, tenantID string) ([]*Domain, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []*Domain
	for _, d := range f.byID {
		if d.ProjectID == projectID && d.TenantID == tenantID {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

var _ DomainStore = (*fakeDomainStore)(nil)

// fakeTenantStore is an in-memory TenantStore keyed by (projectID, id).
type fakeTenantStore struct {
	byID   map[string]*Tenant
	getErr error
	setErr error
}

func newFakeTenantStore() *fakeTenantStore {
	return &fakeTenantStore{byID: map[string]*Tenant{}}
}

func (f *fakeTenantStore) put(t *Tenant) {
	cp := *t
	f.byID[t.ProjectID+"/"+t.ID] = &cp
}

func (f *fakeTenantStore) CreateTenant(_ context.Context, t *Tenant) (string, error) {
	f.put(t)
	return t.ID, nil
}

func (f *fakeTenantStore) GetTenant(_ context.Context, projectID, tenantID string) (*Tenant, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	t, ok := f.byID[projectID+"/"+tenantID]
	if !ok {
		return nil, nil
	}
	out := *t
	return &out, nil
}

func (f *fakeTenantStore) GetTenantByPrimaryDomain(_ context.Context, projectID, domain string) (*Tenant, error) {
	for _, t := range f.byID {
		if t.ProjectID == projectID && t.PrimaryDomain == domain {
			out := *t
			return &out, nil
		}
	}
	return nil, nil
}

func (f *fakeTenantStore) SetTenantStatus(_ context.Context, projectID, tenantID, status string) error {
	if f.setErr != nil {
		return f.setErr
	}
	t, ok := f.byID[projectID+"/"+tenantID]
	if !ok {
		return nil
	}
	t.Status = status
	return nil
}

func (f *fakeTenantStore) ListTenants(_ context.Context, projectID string) ([]*Tenant, error) {
	var out []*Tenant
	for _, t := range f.byID {
		if t.ProjectID == projectID {
			cp := *t
			out = append(out, &cp)
		}
	}
	return out, nil
}

var _ TenantStore = (*fakeTenantStore)(nil)

// fakeMembershipStore is an in-memory MembershipStore keyed by
// (projectID, tenantID, userID).
type fakeMembershipStore struct {
	byKey     map[string]*TenantMembership
	getErr    error
	upsertErr error
	listErr   error
}

func newFakeMembershipStore() *fakeMembershipStore {
	return &fakeMembershipStore{byKey: map[string]*TenantMembership{}}
}

func (f *fakeMembershipStore) key(projectID, tenantID, userID string) string {
	return projectID + "/" + tenantID + "/" + userID
}

func (f *fakeMembershipStore) UpsertMembership(_ context.Context, m *TenantMembership) (string, error) {
	if f.upsertErr != nil {
		return "", f.upsertErr
	}
	k := f.key(m.ProjectID, m.TenantID, m.UserID)
	id := m.ID
	if id == "" {
		id = "mem-" + k
	}
	stored := *m
	stored.ID = id
	f.byKey[k] = &stored
	return id, nil
}

func (f *fakeMembershipStore) GetMembership(_ context.Context, projectID, tenantID, userID string) (*TenantMembership, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	m, ok := f.byKey[f.key(projectID, tenantID, userID)]
	if !ok {
		return nil, nil
	}
	out := *m
	return &out, nil
}

func (f *fakeMembershipStore) ListMembershipsForUser(_ context.Context, projectID, userID string) ([]*TenantMembership, error) {
	var out []*TenantMembership
	for _, m := range f.byKey {
		if m.ProjectID == projectID && m.UserID == userID {
			cp := *m
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeMembershipStore) ListMembershipsForTenant(_ context.Context, projectID, tenantID string) ([]*TenantMembership, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []*TenantMembership
	for _, m := range f.byKey {
		if m.ProjectID == projectID && m.TenantID == tenantID {
			cp := *m
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeMembershipStore) RemoveMembership(_ context.Context, projectID, tenantID, userID string) error {
	delete(f.byKey, f.key(projectID, tenantID, userID))
	return nil
}

var _ MembershipStore = (*fakeMembershipStore)(nil)

// fakeDNSResolver returns a fixed TXT record set (or error) per host.
type fakeDNSResolver struct {
	records map[string][]string
	err     error
}

func (f *fakeDNSResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.records[host], nil
}

var _ dnsResolver = (*fakeDNSResolver)(nil)

// ── Harness ────────────────────────────────────────────────────────────

type domainFixture struct {
	svc      *DomainService
	domains  *fakeDomainStore
	tenants  *fakeTenantStore
	members  *fakeMembershipStore
	resolver *fakeDNSResolver
}

func newDomainFixture() *domainFixture {
	d := newFakeDomainStore()
	t := newFakeTenantStore()
	m := newFakeMembershipStore()
	r := &fakeDNSResolver{records: map[string][]string{}}
	svc := NewDomainService(d, t, m, r, &config.Config{}, nil)
	return &domainFixture{svc: svc, domains: d, tenants: t, members: m, resolver: r}
}

// seedAdmin makes userID an active owner of (project, tenant).
func (f *domainFixture) seedAdmin(projectID, tenantID, userID string) {
	_, _ = f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: projectID,
		TenantID:  tenantID,
		UserID:    userID,
		Source:    MembershipSourceAdded,
		Role:      RoleOwner,
		Status:    MembershipStatusActive,
	})
}

const (
	testProject = "proj-1"
	testTenant  = "tenant-1"
	testCaller  = "user-1"
	testDomain  = "acme.com"
)

// ── CreateDomain ───────────────────────────────────────────────────────

func TestCreateDomain_ReturnsDeterministicChallenge(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)

	out, err := f.svc.CreateDomain(withProject(testProject), testCaller, testTenant, "ACME.com", DomainVerificationDNSTXT)
	require.NoError(t, err)
	require.NotNil(t, out.Domain)
	require.Equal(t, testDomain, out.Domain.Domain, "domain is normalized to lower-case")
	require.Equal(t, DomainStatusPending, out.Domain.Status)
	require.Equal(t, testDomain, out.TXTName)

	_, wantValue := dnsTXTChallenge(testProject, testDomain)
	require.Equal(t, wantValue, out.TXTValue)
	require.Contains(t, out.TXTValue, domainVerifyTXTPrefix)

	// The challenge must be stable across calls and independent of the
	// caller's input casing.
	_, again := dnsTXTChallenge(testProject, "ACME.COM")
	require.Equal(t, wantValue, again)
}

func TestCreateDomain_EmailMethodHasNoTXTChallenge(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)

	out, err := f.svc.CreateDomain(withProject(testProject), testCaller, testTenant, testDomain, DomainVerificationEmail)
	require.NoError(t, err)
	require.Equal(t, DomainVerificationEmail, out.Domain.VerificationMethod)
	require.Empty(t, out.TXTName)
	require.Empty(t, out.TXTValue)
}

func TestCreateDomain_RejectsNonAdminCaller(t *testing.T) {
	f := newDomainFixture()
	// No membership seeded for the caller.

	_, err := f.svc.CreateDomain(withProject(testProject), testCaller, testTenant, testDomain, DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestCreateDomain_RejectsPlainMemberCaller(t *testing.T) {
	f := newDomainFixture()
	_, _ = f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: testProject, TenantID: testTenant, UserID: testCaller,
		Source: MembershipSourceDomain, Role: RoleMember, Status: MembershipStatusActive,
	})

	_, err := f.svc.CreateDomain(withProject(testProject), testCaller, testTenant, testDomain, DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestCreateDomain_RejectsWithoutProject(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)

	_, err := f.svc.CreateDomain(context.Background(), testCaller, testTenant, testDomain, DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestCreateDomain_RejectsBadInput(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	ctx := withProject(testProject)

	_, err := f.svc.CreateDomain(ctx, testCaller, "", testDomain, DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrInvalidArgument, "blank tenant")

	_, err = f.svc.CreateDomain(ctx, testCaller, testTenant, "not a domain", DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrInvalidArgument, "domain with whitespace")

	_, err = f.svc.CreateDomain(ctx, testCaller, testTenant, "localhost", DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrInvalidArgument, "domain without a dot")

	_, err = f.svc.CreateDomain(ctx, testCaller, testTenant, "   ", DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrInvalidArgument, "whitespace-only domain")

	_, err = f.svc.CreateDomain(ctx, testCaller, testTenant, testDomain, "carrier-pigeon")
	require.ErrorIs(t, err, ErrInvalidArgument, "unknown method")
}

func TestCreateDomain_RejectsMissingCaller(t *testing.T) {
	f := newDomainFixture()
	_, err := f.svc.CreateDomain(withProject(testProject), "", testTenant, testDomain, DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrUnauthenticated)
}

// ── VerifyDomain ───────────────────────────────────────────────────────

// seedPendingDomain creates a pending DNS-TXT domain and returns its id.
func (f *domainFixture) seedPendingDomain(t *testing.T, projectID, tenantID, domain string) string {
	t.Helper()
	id, err := f.domains.CreateDomain(context.Background(), &Domain{
		ProjectID: projectID, TenantID: tenantID, Domain: domain,
		VerificationMethod: DomainVerificationDNSTXT, Status: DomainStatusPending,
	})
	require.NoError(t, err)
	return id
}

func TestVerifyDomain_SuccessClaimsTenantAndMakesCallerOwner(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)

	_, want := dnsTXTChallenge(testProject, testDomain)
	f.resolver.records[testDomain] = []string{"some-unrelated-record", want}

	got, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.NoError(t, err)
	require.Equal(t, DomainStatusVerified, got.Status)
	require.NotZero(t, got.VerifiedAtMs)

	tnt, _ := f.tenants.GetTenant(context.Background(), testProject, testTenant)
	require.Equal(t, TenantStatusClaimed, tnt.Status)

	m, _ := f.members.GetMembership(context.Background(), testProject, testTenant, testCaller)
	require.NotNil(t, m)
	require.Equal(t, RoleOwner, m.Role)
	require.Equal(t, MembershipSourceAdded, m.Source)
	require.Equal(t, MembershipStatusActive, m.Status)
}

func TestVerifyDomain_TXTAbsentFailsAndMarksDomainFailed(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)

	f.resolver.records[testDomain] = []string{"identity-domain-verify=deadbeef"} // wrong value

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, ErrPermissionDenied)

	d, _ := f.domains.GetDomain(context.Background(), testProject, id)
	require.Equal(t, DomainStatusFailed, d.Status)

	// The tenant must NOT have been claimed on a failed verification.
	tnt, _ := f.tenants.GetTenant(context.Background(), testProject, testTenant)
	require.Equal(t, TenantStatusLatent, tnt.Status)
}

func TestVerifyDomain_LookupErrorIsVerificationFailure(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)
	f.resolver.err = errors.New("no such host")

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestVerifyDomain_FirstVerifierOnLatentTenantBecomesOwner(t *testing.T) {
	f := newDomainFixture()
	// No membership seeded: the tenant is latent with no members yet, so
	// the first verifier is allowed and becomes its owner.
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)

	_, want := dnsTXTChallenge(testProject, testDomain)
	f.resolver.records[testDomain] = []string{want}

	got, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.NoError(t, err)
	require.Equal(t, DomainStatusVerified, got.Status)

	m, _ := f.members.GetMembership(context.Background(), testProject, testTenant, testCaller)
	require.NotNil(t, m)
	require.Equal(t, RoleOwner, m.Role)
}

func TestVerifyDomain_NonMemberRejectedOnClaimedTenant(t *testing.T) {
	f := newDomainFixture()
	// Tenant already claimed and has an owner who is NOT the caller.
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusClaimed})
	f.seedAdmin(testProject, testTenant, "someone-else")
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)

	_, want := dnsTXTChallenge(testProject, testDomain)
	f.resolver.records[testDomain] = []string{want}

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestVerifyDomain_NonMemberRejectedOnLatentTenantWithMembers(t *testing.T) {
	f := newDomainFixture()
	// Latent but already has a member: the open-first-verify exception
	// does NOT apply, so a non-member is rejected.
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	f.seedAdmin(testProject, testTenant, "founder")
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)

	_, want := dnsTXTChallenge(testProject, testDomain)
	f.resolver.records[testDomain] = []string{want}

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestVerifyDomain_EmailMethodUnimplemented(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	id, err := f.domains.CreateDomain(context.Background(), &Domain{
		ProjectID: testProject, TenantID: testTenant, Domain: testDomain,
		VerificationMethod: DomainVerificationEmail, Status: DomainStatusPending,
	})
	require.NoError(t, err)

	_, err = f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, ErrUnimplemented)
}

func TestVerifyDomain_UnknownDomainNotFound(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestVerifyDomain_RejectsWithoutProject(t *testing.T) {
	f := newDomainFixture()
	_, err := f.svc.VerifyDomain(context.Background(), testCaller, "dom")
	require.ErrorIs(t, err, ErrPermissionDenied)
}

// ── ListTenantDomains ──────────────────────────────────────────────────

func TestListTenantDomains_ReturnsTenantDomains(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.seedPendingDomain(t, testProject, testTenant, "acme.com")
	f.seedPendingDomain(t, testProject, testTenant, "acme.io")
	// A domain in another tenant must not leak.
	f.seedPendingDomain(t, testProject, "other-tenant", "evil.com")

	got, err := f.svc.ListTenantDomains(withProject(testProject), testCaller, testTenant)
	require.NoError(t, err)
	require.Len(t, got, 2)
	names := []string{got[0].Domain, got[1].Domain}
	require.ElementsMatch(t, []string{"acme.com", "acme.io"}, names)
}

func TestListTenantDomains_RejectsNonAdmin(t *testing.T) {
	f := newDomainFixture()
	_, err := f.svc.ListTenantDomains(withProject(testProject), testCaller, testTenant)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

// ── DNS resolver default ───────────────────────────────────────────────

func TestNewDomainService_DefaultsResolver(t *testing.T) {
	svc := NewDomainService(newFakeDomainStore(), newFakeTenantStore(), newFakeMembershipStore(), nil, nil, nil)
	require.NotNil(t, svc.resolver, "a nil resolver must default to net.DefaultResolver")
	require.NotNil(t, svc.logger, "a nil logger must default to a no-op")
}

// ── Store-error propagation ─────────────────────────────────────────────
//
// Infrastructure failures from the stores must surface to the caller, not
// be swallowed or masked as a verification failure.

var errBoom = errors.New("boom")

func TestCreateDomain_PropagatesStoreError(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.domains.createErr = errBoom

	_, err := f.svc.CreateDomain(withProject(testProject), testCaller, testTenant, testDomain, DomainVerificationDNSTXT)
	require.ErrorIs(t, err, errBoom)
}

func TestCreateDomain_PropagatesMembershipLookupError(t *testing.T) {
	f := newDomainFixture()
	f.members.getErr = errBoom

	_, err := f.svc.CreateDomain(withProject(testProject), testCaller, testTenant, testDomain, DomainVerificationDNSTXT)
	require.ErrorIs(t, err, errBoom)
}

func TestVerifyDomain_PropagatesGetDomainError(t *testing.T) {
	f := newDomainFixture()
	f.domains.getErr = errBoom

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, "any")
	require.ErrorIs(t, err, errBoom)
}

func TestVerifyDomain_PropagatesSetDomainStatusError(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)
	_, want := dnsTXTChallenge(testProject, testDomain)
	f.resolver.records[testDomain] = []string{want}
	f.domains.setErr = errBoom

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, errBoom)
}

func TestVerifyDomain_PropagatesSetTenantStatusError(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)
	_, want := dnsTXTChallenge(testProject, testDomain)
	f.resolver.records[testDomain] = []string{want}
	f.tenants.setErr = errBoom

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, errBoom)
}

func TestVerifyDomain_PropagatesUpsertMembershipError(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusClaimed})
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)
	_, want := dnsTXTChallenge(testProject, testDomain)
	f.resolver.records[testDomain] = []string{want}
	f.members.upsertErr = errBoom

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, errBoom)
}

func TestVerifyDomain_FirstVerifyPropagatesTenantLookupError(t *testing.T) {
	f := newDomainFixture()
	// Non-member caller forces the open-first-verify path, where the tenant
	// lookup fails.
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)
	f.tenants.getErr = errBoom

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, errBoom)
}

func TestVerifyDomain_FirstVerifyPropagatesMemberListError(t *testing.T) {
	f := newDomainFixture()
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)
	f.members.listErr = errBoom

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, errBoom)
}

func TestVerifyDomain_FirstVerifyMissingTenantNotFound(t *testing.T) {
	f := newDomainFixture()
	// Domain exists but its tenant row is missing — the open-first-verify
	// check resolves a (nil, nil) tenant.
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestVerifyDomain_RejectsUnknownVerificationMethod(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	id, err := f.domains.CreateDomain(context.Background(), &Domain{
		ProjectID: testProject, TenantID: testTenant, Domain: testDomain,
		VerificationMethod: "smoke-signal", Status: DomainStatusPending,
	})
	require.NoError(t, err)

	_, err = f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestListTenantDomains_PropagatesStoreError(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.domains.listErr = errBoom

	_, err := f.svc.ListTenantDomains(withProject(testProject), testCaller, testTenant)
	require.ErrorIs(t, err, errBoom)
}

func TestListTenantDomains_RejectsMissingProjectAndCaller(t *testing.T) {
	f := newDomainFixture()
	_, err := f.svc.ListTenantDomains(context.Background(), testCaller, testTenant)
	require.ErrorIs(t, err, ErrPermissionDenied)

	_, err = f.svc.ListTenantDomains(withProject(testProject), "", testTenant)
	require.ErrorIs(t, err, ErrUnauthenticated)

	_, err = f.svc.ListTenantDomains(withProject(testProject), testCaller, "")
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestVerifyDomain_RejectsMissingCallerAndDomainID(t *testing.T) {
	f := newDomainFixture()
	_, err := f.svc.VerifyDomain(withProject(testProject), "", "d")
	require.ErrorIs(t, err, ErrUnauthenticated)

	_, err = f.svc.VerifyDomain(withProject(testProject), testCaller, "")
	require.ErrorIs(t, err, ErrInvalidArgument)
}
