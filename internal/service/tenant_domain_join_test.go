package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
)

// ── SetDomainJoin ─────────────────────────────────────────────────────────

const joinDomainID = "dom-join"

// newDomainJoinFixture is a domain fixture with an audit trail, in which
// testCaller owns testTenant and the tenant has verified testDomain.
func newDomainJoinFixture() (*domainFixture, *recordingAuditWriter) {
	f := newDomainFixture()
	w := newRecordingAuditWriter()
	f.svc.WithAudit(audit.NewLogger(w, "test-tenant", nil))
	f.seedAdmin(testProject, testTenant, testCaller)
	_, _ = f.domains.CreateDomain(context.Background(), &Domain{
		ID: joinDomainID, ProjectID: testProject, TenantID: testTenant, Domain: testDomain,
		VerificationMethod: DomainVerificationDNSTXT, Status: DomainStatusVerified,
	})
	return f, w
}

func TestSetDomainJoin_TurnsJoinOnAndOffAndAudits(t *testing.T) {
	f, w := newDomainJoinFixture()
	ctx := withProject(testProject)
	event := string(audit.EventDomainJoinSet)

	on, err := f.svc.SetDomainJoin(ctx, testCaller, " "+joinDomainID+" ", true, "203.0.113.7", "test-agent")
	require.NoError(t, err)
	assert.True(t, on.AllowJoin)
	assert.Equal(t, joinDomainID, on.ID)
	assert.Equal(t, 1, w.countByEventTypeActorTarget(event, testCaller, joinDomainID))
	details := w.detailsOf(event)
	require.Len(t, details, 1)
	assert.Equal(t, map[string]any{
		"project_id": testProject, "tenant_id": testTenant, "domain": testDomain, "allow_join": true,
	}, details[0])

	// Asking for the value the domain has changes and records nothing.
	again, err := f.svc.SetDomainJoin(ctx, testCaller, joinDomainID, true, "", "")
	require.NoError(t, err)
	assert.True(t, again.AllowJoin)
	assert.Equal(t, 1, w.countByEventType(event))

	off, err := f.svc.SetDomainJoin(ctx, testCaller, joinDomainID, false, "", "")
	require.NoError(t, err)
	assert.False(t, off.AllowJoin)
	stored, err := f.domains.GetDomain(ctx, testProject, joinDomainID)
	require.NoError(t, err)
	assert.False(t, stored.AllowJoin)
	details = w.detailsOf(event)
	require.Len(t, details, 2)
	assert.Equal(t, false, details[1]["allow_join"])
}

// The setting may be made before the domain is verified; it takes effect
// once the domain is.
func TestSetDomainJoin_OnAPendingDomain(t *testing.T) {
	f, _ := newDomainJoinFixture()
	f.domains.byID[f.domains.key(testProject, joinDomainID)].Status = DomainStatusPending

	out, err := f.svc.SetDomainJoin(withProject(testProject), testCaller, joinDomainID, true, "", "")
	require.NoError(t, err)
	assert.True(t, out.AllowJoin)
	assert.Equal(t, DomainStatusPending, out.Status)
}

func TestSetDomainJoin_WithoutAnAuditTrail(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	_, _ = f.domains.CreateDomain(context.Background(), &Domain{ID: joinDomainID, ProjectID: testProject, TenantID: testTenant, Domain: testDomain})

	out, err := f.svc.SetDomainJoin(withProject(testProject), testCaller, joinDomainID, true, "", "")
	require.NoError(t, err)
	assert.True(t, out.AllowJoin)
}

func TestSetDomainJoin_RefusesBadRequests(t *testing.T) {
	f, w := newDomainJoinFixture()
	ctx := withProject(testProject)

	_, err := f.svc.SetDomainJoin(context.Background(), testCaller, joinDomainID, true, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "no project in scope")
	_, err = f.svc.SetDomainJoin(ctx, "", joinDomainID, true, "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = f.svc.SetDomainJoin(ctx, testCaller, " ", true, "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = f.svc.SetDomainJoin(ctx, testCaller, "dom-unknown", true, "", "")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = f.svc.SetDomainJoin(withProject("proj-other"), testCaller, joinDomainID, true, "", "")
	require.ErrorIs(t, err, ErrNotFound, "another project's domain is not found")

	assert.Zero(t, w.countByEventType(string(audit.EventDomainJoinSet)))
}

// Only an active owner or admin of a governable tenant sets it.
func TestSetDomainJoin_OnlyAnAdminOfAGovernableTenant(t *testing.T) {
	for name, setup := range map[string]func(f *domainFixture){
		"member": func(f *domainFixture) {
			f.members.byKey[f.members.key(testProject, testTenant, testCaller)].Role = RoleMember
		},
		"inactive admin": func(f *domainFixture) {
			f.members.byKey[f.members.key(testProject, testTenant, testCaller)].Status = MembershipStatusInactive
		},
		"not a member": func(f *domainFixture) {
			delete(f.members.byKey, f.members.key(testProject, testTenant, testCaller))
		},
		"suspended": func(f *domainFixture) {
			f.tenants.byID[testProject+"/"+testTenant].Status = TenantStatusSuspended
		},
	} {
		f, w := newDomainJoinFixture()
		setup(f)
		_, err := f.svc.SetDomainJoin(withProject(testProject), testCaller, joinDomainID, true, "", "")
		require.ErrorIs(t, err, ErrPermissionDenied, name)
		stored, _ := f.domains.GetDomain(context.Background(), testProject, joinDomainID)
		assert.False(t, stored.AllowJoin, name)
		assert.Zero(t, w.countByEventType(string(audit.EventDomainJoinSet)), name)
	}
}

func TestSetDomainJoin_PropagatesStoreErrors(t *testing.T) {
	boom := errors.New("boom")
	for name, setup := range map[string]func(f *domainFixture){
		"get domain":     func(f *domainFixture) { f.domains.getErr = boom },
		"get membership": func(f *domainFixture) { f.members.getErr = boom },
		"get tenant":     func(f *domainFixture) { f.tenants.getErr = boom },
		"set allow join": func(f *domainFixture) { f.domains.allowJoinErr = boom },
	} {
		f, w := newDomainJoinFixture()
		setup(f)
		_, err := f.svc.SetDomainJoin(withProject(testProject), testCaller, joinDomainID, true, "", "")
		require.ErrorIs(t, err, boom, name)
		assert.Zero(t, w.countByEventType(string(audit.EventDomainJoinSet)), name)
	}
}

// rereadDomainStore answers the first GetDomain from its fake and the next
// with err, or with no row when err is nil: the domain deleted, or the read
// failing, between the change and the read that returns it.
type rereadDomainStore struct {
	*fakeDomainStore
	reads int
	err   error
}

func (s *rereadDomainStore) GetDomain(ctx context.Context, projectID, domainID string) (*Domain, error) {
	s.reads++
	if s.reads > 1 {
		return nil, s.err
	}
	return s.fakeDomainStore.GetDomain(ctx, projectID, domainID)
}

func TestSetDomainJoin_TheReadAfterTheChange(t *testing.T) {
	boom := errors.New("boom")
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"fails":      {err: boom, want: boom},
		"finds none": {want: ErrNotFound},
	} {
		f, w := newDomainJoinFixture()
		store := &rereadDomainStore{fakeDomainStore: f.domains, err: tc.err}
		svc := NewDomainService(store, f.tenants, f.members, f.resolver, &config.Config{}, nil).
			WithAudit(audit.NewLogger(w, "test-tenant", nil))

		_, err := svc.SetDomainJoin(withProject(testProject), testCaller, joinDomainID, true, "", "")
		require.ErrorIs(t, err, tc.want, name)
		assert.Equal(t, 1, w.countByEventType(string(audit.EventDomainJoinSet)), "%s: the change was made, so it is recorded", name)
	}
}

// ── ListJoinableTenants and JoinTenantByDomain ──────────────────────────

const (
	joinTenantName = "Acme"
	joinerID       = "user-joiner"
	joinEmail      = "joiner@example.test"
	joinDomainName = "example.test"
)

// joinFixture is a self-service fixture holding a claimed tenant that
// ssOwnerID owns and that has verified joinDomainName and lets it join, with
// joinerID an active, verified person on that domain who is not a member.
type joinFixture struct {
	*selfServiceFixture
	domains *fakeDomainStore
}

func newJoinFixture() *joinFixture {
	f := newSelfServiceFixture(&config.Config{})
	f.tenants.ensure(ssProject, ownTenant)
	f.tenants.byID[ssProject+"/"+ownTenant].Name = joinTenantName
	f.users.set(ssProject, &User{ID: joinerID, Email: joinEmail, Status: StatusActive, EmailVerified: true})
	_, _ = f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: ssProject, TenantID: ownTenant, UserID: ssOwnerID,
		Source: MembershipSourceCreated, Role: RoleOwner, Status: MembershipStatusActive,
	})
	d := newFakeDomainStore()
	_, _ = d.CreateDomain(context.Background(), &Domain{
		ID: joinDomainID, ProjectID: ssProject, TenantID: ownTenant, Domain: joinDomainName,
		VerificationMethod: DomainVerificationDNSTXT, Status: DomainStatusVerified, AllowJoin: true,
	})
	f.svc.WithDomains(d)
	return &joinFixture{selfServiceFixture: f, domains: d}
}

func (f *joinFixture) domain() *Domain {
	return f.domains.byID[f.domains.key(ssProject, joinDomainID)]
}

func (f *joinFixture) tenant() *Tenant {
	return f.tenants.byID[ssProject+"/"+ownTenant]
}

func (f *joinFixture) joinable(t *testing.T, userID string) []*JoinableTenant {
	t.Helper()
	out, err := f.svc.ListJoinableTenants(withTenantsProject(false), userID)
	require.NoError(t, err)
	require.NotNil(t, out, "an empty list, never nil")
	return out
}

// noJoin lists the ways a tenant stops being joinable by joinerID: each
// makes ListJoinableTenants empty and JoinTenantByDomain PERMISSION_DENIED.
func noJoin() map[string]func(f *joinFixture) {
	return map[string]func(f *joinFixture){
		"join is off":         func(f *joinFixture) { f.domain().AllowJoin = false },
		"domain not verified": func(f *joinFixture) { f.domain().Status = DomainStatusPending },
		"no domain":           func(f *joinFixture) { delete(f.domains.byID, f.domains.key(ssProject, joinDomainID)) },
		"tenant suspended":    func(f *joinFixture) { f.tenant().Status = TenantStatusSuspended },
		"tenant latent":       func(f *joinFixture) { f.tenant().Status = TenantStatusLatent },
		"tenant gone":         func(f *joinFixture) { delete(f.tenants.byID, ssProject+"/"+ownTenant) },
		"another domain": func(f *joinFixture) {
			f.users.set(ssProject, &User{ID: joinerID, Email: "joiner@elsewhere.test", Status: StatusActive, EmailVerified: true})
		},
		"a public provider's domain": func(f *joinFixture) {
			f.domain().Domain = "gmail.com"
			f.users.set(ssProject, &User{ID: joinerID, Email: "joiner@gmail.com", Status: StatusActive, EmailVerified: true})
		},
	}
}

func TestListJoinableTenants_ListsTheTenantTheEmailsDomainLetsJoin(t *testing.T) {
	f := newJoinFixture()

	assert.Equal(t, []*JoinableTenant{{TenantID: ownTenant, Name: joinTenantName}}, f.joinable(t, joinerID))
	assert.Empty(t, f.joinable(t, ssOwnerID), "an active member has nothing to join")

	// A member whose membership ended may join again.
	f.members.byKey[f.members.key(ssProject, ownTenant, ssOwnerID)].Status = MembershipStatusInactive
	assert.Len(t, f.joinable(t, ssOwnerID), 1)
}

func TestListJoinableTenants_EmptyWhenNothingIsJoinable(t *testing.T) {
	for name, setup := range noJoin() {
		f := newJoinFixture()
		setup(f)
		assert.Empty(t, f.joinable(t, joinerID), name)
	}
}

func TestListJoinableTenants_EmptyForAnAccountThatCannotJoin(t *testing.T) {
	f := newJoinFixture()
	for _, id := range ineligibleOwners(f.users, ssProject) {
		u := f.users.byID[f.users.key(ssProject, id)]
		u.Email = id + "@" + joinDomainName
		assert.Empty(t, f.joinable(t, id), id)
	}
}

func TestListJoinableTenants_RefusesBadRequests(t *testing.T) {
	f := newJoinFixture()
	ctx := withTenantsProject(false)

	_, err := f.svc.ListJoinableTenants(context.Background(), joinerID)
	require.ErrorIs(t, err, ErrPermissionDenied, "no project in scope")
	_, err = f.svc.ListJoinableTenants(ctx, "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = f.svc.ListJoinableTenants(ctx, "user-unknown")
	require.ErrorIs(t, err, ErrNotFound)

	f.svc.WithDomains(nil)
	_, err = f.svc.ListJoinableTenants(ctx, joinerID)
	require.ErrorIs(t, err, ErrUnimplemented, "without a domain store")
}

func TestListJoinableTenants_PropagatesStoreErrors(t *testing.T) {
	boom := errors.New("boom")
	for name, setup := range map[string]func(f *joinFixture){
		"get user":            func(f *joinFixture) { f.users.getErr = boom },
		"get verified domain": func(f *joinFixture) { f.domains.verifiedErr = boom },
		"get tenant":          func(f *joinFixture) { f.tenants.getErr = boom },
		"get membership":      func(f *joinFixture) { f.members.getErr = boom },
	} {
		f := newJoinFixture()
		setup(f)
		_, err := f.svc.ListJoinableTenants(withTenantsProject(false), joinerID)
		require.ErrorIs(t, err, boom, name)
	}
}

func TestJoinTenantByDomain_JoinsAsADomainMemberAndAudits(t *testing.T) {
	f := newJoinFixture()
	ctx := withTenantsProject(false)
	event := string(audit.EventTenantJoinedByDomain)

	m, err := f.svc.JoinTenantByDomain(ctx, joinerID, " "+ownTenant+" ", "203.0.113.7", "test-agent")
	require.NoError(t, err)
	assert.Equal(t, ownTenant, m.TenantID)
	assert.Equal(t, joinerID, m.UserID)
	assert.Equal(t, RoleMember, m.Role)
	assert.Equal(t, MembershipSourceDomain, m.Source, "it ends when the email leaves the domain")
	assert.Equal(t, MembershipStatusActive, m.Status)
	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(event, joinerID, joinerID))
	details := f.audit.detailsOf(event)
	require.Len(t, details, 1)
	assert.Equal(t, map[string]any{"project_id": ssProject, "tenant_id": ownTenant, "domain": joinDomainName}, details[0])
	assert.Empty(t, f.joinable(t, joinerID), "a member has nothing left to join")

	// A retry returns the membership and records nothing.
	again, err := f.svc.JoinTenantByDomain(ctx, joinerID, ownTenant, "", "")
	require.NoError(t, err)
	assert.Equal(t, m.ID, again.ID)
	assert.Equal(t, 1, f.audit.countByEventType(event))

	// Turning join off ends no membership.
	f.domain().AllowJoin = false
	held, err := f.members.GetMembership(ctx, ssProject, ownTenant, joinerID)
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusActive, held.Status)
}

// A membership that ended is made active again, as a domain member.
func TestJoinTenantByDomain_RejoinsAnEndedMembership(t *testing.T) {
	f := newJoinFixture()
	_, _ = f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: ssProject, TenantID: ownTenant, UserID: joinerID,
		Source: MembershipSourceDomain, Role: RoleMember, Status: MembershipStatusInactive,
	})
	prior, _ := f.members.GetMembership(context.Background(), ssProject, ownTenant, joinerID)

	m, err := f.svc.JoinTenantByDomain(withTenantsProject(false), joinerID, ownTenant, "", "")
	require.NoError(t, err)
	assert.Equal(t, prior.ID, m.ID)
	assert.Equal(t, MembershipStatusActive, m.Status)
	assert.Equal(t, 1, f.audit.countByEventType(string(audit.EventTenantJoinedByDomain)))
}

// A member who joined another way keeps their role and source.
func TestJoinTenantByDomain_LeavesAnExistingMembershipAsItIs(t *testing.T) {
	f := newJoinFixture()

	m, err := f.svc.JoinTenantByDomain(withTenantsProject(false), ssOwnerID, ownTenant, "", "")
	require.NoError(t, err)
	assert.Equal(t, RoleOwner, m.Role)
	assert.Equal(t, MembershipSourceCreated, m.Source)
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantJoinedByDomain)))
}

func TestJoinTenantByDomain_WithoutAnAuditTrail(t *testing.T) {
	f := newJoinFixture()
	f.svc.WithAudit(nil)

	m, err := f.svc.JoinTenantByDomain(withTenantsProject(false), joinerID, ownTenant, "", "")
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusActive, m.Status)
}

func TestJoinTenantByDomain_RefusesATenantTheDomainDoesNotLetJoin(t *testing.T) {
	cases := noJoin()
	cases["another tenant"] = func(*joinFixture) {}
	for name, setup := range cases {
		f := newJoinFixture()
		setup(f)
		tenantID := ownTenant
		if name == "another tenant" {
			f.tenants.ensure(ssProject, "t-other")
			tenantID = "t-other"
		}
		_, err := f.svc.JoinTenantByDomain(withTenantsProject(false), joinerID, tenantID, "", "")
		require.ErrorIs(t, err, ErrPermissionDenied, name)
		held, _ := f.members.GetMembership(context.Background(), ssProject, tenantID, joinerID)
		assert.Nil(t, held, name)
		assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantJoinedByDomain)), name)
	}

	// An unknown tenant is refused the same way, so a call reveals nothing.
	f := newJoinFixture()
	_, err := f.svc.JoinTenantByDomain(withTenantsProject(false), joinerID, "t-unknown", "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestJoinTenantByDomain_RefusesAnAccountThatCannotJoin(t *testing.T) {
	f := newJoinFixture()
	for _, id := range ineligibleOwners(f.users, ssProject) {
		u := f.users.byID[f.users.key(ssProject, id)]
		u.Email = id + "@" + joinDomainName
		_, err := f.svc.JoinTenantByDomain(withTenantsProject(false), id, ownTenant, "", "")
		if id == "unverified" {
			require.ErrorIs(t, err, ErrEmailVerificationRequired, id)
			continue
		}
		require.ErrorIs(t, err, ErrPermissionDenied, id)
	}
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantJoinedByDomain)))
}

func TestJoinTenantByDomain_RefusesBadRequests(t *testing.T) {
	f := newJoinFixture()
	ctx := withTenantsProject(false)

	_, err := f.svc.JoinTenantByDomain(context.Background(), joinerID, ownTenant, "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "no project in scope")
	_, err = f.svc.JoinTenantByDomain(ctx, "", ownTenant, "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = f.svc.JoinTenantByDomain(ctx, joinerID, " ", "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = f.svc.JoinTenantByDomain(ctx, "user-unknown", ownTenant, "", "")
	require.ErrorIs(t, err, ErrNotFound)

	f.svc.WithDomains(nil)
	_, err = f.svc.JoinTenantByDomain(ctx, joinerID, ownTenant, "", "")
	require.ErrorIs(t, err, ErrUnimplemented, "without a domain store")
}

func TestJoinTenantByDomain_PropagatesStoreErrors(t *testing.T) {
	boom := errors.New("boom")
	for name, setup := range map[string]func(f *joinFixture){
		"get user":            func(f *joinFixture) { f.users.getErr = boom },
		"get verified domain": func(f *joinFixture) { f.domains.verifiedErr = boom },
		"get tenant":          func(f *joinFixture) { f.tenants.getErr = boom },
		"get membership":      func(f *joinFixture) { f.members.getErr = boom },
		"grant membership":    func(f *joinFixture) { f.members.upsertErr = boom },
	} {
		f := newJoinFixture()
		setup(f)
		_, err := f.svc.JoinTenantByDomain(withTenantsProject(false), joinerID, ownTenant, "", "")
		require.ErrorIs(t, err, boom, name)
		assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantJoinedByDomain)), name)
	}
}
