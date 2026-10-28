package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

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
	// writes counts SetDomainStatus calls that changed a row; attempts holds
	// every attempt RecordDomainAttempt admitted, attemptErr fails it.
	writes     int
	attempts   []DomainAttempt
	attemptErr error
	// verifiedErr fails GetVerifiedDomain; allowJoinErr fails
	// SetDomainAllowJoin.
	verifiedErr  error
	allowJoinErr error
}

func newFakeDomainStore() *fakeDomainStore {
	return &fakeDomainStore{byID: map[string]*Domain{}}
}

func (f *fakeDomainStore) key(projectID, id string) string { return projectID + "/" + id }

func (f *fakeDomainStore) CreateDomain(_ context.Context, d *Domain) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	for _, other := range f.byID {
		if other.ProjectID == d.ProjectID && strings.EqualFold(other.Domain, d.Domain) &&
			(other.TenantID == d.TenantID || other.Status == DomainStatusVerified) {
			return "", ErrAlreadyExists
		}
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

func (f *fakeDomainStore) GetVerifiedDomain(_ context.Context, projectID, domain string) (*Domain, error) {
	if f.verifiedErr != nil {
		return nil, f.verifiedErr
	}
	for _, d := range f.byID {
		if d.ProjectID == projectID && strings.EqualFold(d.Domain, domain) && d.Status == DomainStatusVerified {
			out := *d
			return &out, nil
		}
	}
	return nil, nil
}

// RecordDomainAttempt mirrors the postgres store: it counts the tenant's
// attempts at or after WindowStartMs and refuses one past MaxPerWindow.
func (f *fakeDomainStore) RecordDomainAttempt(_ context.Context, a DomainAttempt) error {
	if f.attemptErr != nil {
		return f.attemptErr
	}
	n := 0
	for _, prior := range f.attempts {
		if prior.ProjectID == a.ProjectID && prior.TenantID == a.TenantID && prior.AtMs >= a.WindowStartMs {
			n++
		}
	}
	if n >= a.MaxPerWindow {
		return ErrDomainAttemptsLimited
	}
	f.attempts = append(f.attempts, a)
	return nil
}

func (f *fakeDomainStore) SetDomainStatus(_ context.Context, projectID, domainID, status string, verifiedAtMs int64) error {
	if f.setErr != nil {
		return f.setErr
	}
	d, ok := f.byID[f.key(projectID, domainID)]
	if !ok || d.Status == status || (d.Status == DomainStatusVerified && status != DomainStatusVerified) {
		return nil
	}
	if status == DomainStatusVerified {
		for _, other := range f.byID {
			if other != d && other.ProjectID == projectID && strings.EqualFold(other.Domain, d.Domain) && other.Status == DomainStatusVerified {
				return ErrAlreadyExists
			}
		}
	}
	d.Status = status
	f.writes++
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

// SetDomainAllowJoin mirrors the postgres store: it returns the domain as
// it then stands and whether the call changed it, and nil for an unknown id.
func (f *fakeDomainStore) SetDomainAllowJoin(_ context.Context, projectID, domainID string, allowJoin bool) (*Domain, bool, error) {
	if f.allowJoinErr != nil {
		return nil, false, f.allowJoinErr
	}
	d, ok := f.byID[f.key(projectID, domainID)]
	if !ok {
		return nil, false, nil
	}
	changed := d.AllowJoin != allowJoin
	d.AllowJoin = allowJoin
	cp := *d
	return &cp, changed, nil
}

var _ DomainStore = (*fakeDomainStore)(nil)

// fakeTenantStore is an in-memory TenantStore keyed by (projectID, id).
// CreateOwnedTenant writes the owner membership into members when the two
// fakes are linked (linkFakeTenantStores).
type fakeTenantStore struct {
	byID map[string]*Tenant
	// getErr fails every read: GetTenant, GetTenantByPrimaryDomain and
	// ListTenants.
	getErr    error
	setErr    error
	createErr error
	members   *fakeMembershipStore
	nextID    int
	// writes counts SetTenantStatus calls that changed a row.
	writes int
}

// linkFakeTenantStores lets CreateOwnedTenant write memberships into m and
// lets m's active-tenant reads see each tenant's status.
func linkFakeTenantStores(t *fakeTenantStore, m *fakeMembershipStore) {
	t.members = m
	m.tenants = t
}

func newFakeTenantStore() *fakeTenantStore {
	return &fakeTenantStore{byID: map[string]*Tenant{}}
}

func (f *fakeTenantStore) put(t *Tenant) {
	cp := *t
	f.byID[t.ProjectID+"/"+t.ID] = &cp
}

// ensure puts a claimed tenant unless the store already holds the id.
func (f *fakeTenantStore) ensure(projectID, tenantID string) {
	if _, ok := f.byID[projectID+"/"+tenantID]; !ok {
		f.put(&Tenant{ID: tenantID, ProjectID: projectID, Status: TenantStatusClaimed})
	}
}

func (f *fakeTenantStore) CreateTenant(_ context.Context, t *Tenant) (string, error) {
	f.put(t)
	return t.ID, nil
}

func (f *fakeTenantStore) GetTenantStatus(ctx context.Context, projectID, tenantID string) (string, error) {
	t, err := f.GetTenant(ctx, projectID, tenantID)
	if err != nil || t == nil {
		return "", err
	}
	return t.Status, nil
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

// SetTenantStatus mirrors the postgres store: only a tenant in from moves.
func (f *fakeTenantStore) SetTenantStatus(_ context.Context, projectID, tenantID, from, to string) (bool, error) {
	if f.setErr != nil {
		return false, f.setErr
	}
	if !IsTenantStatus(from) || !IsTenantStatus(to) || from == to {
		return false, fmt.Errorf("%w: %q to %q", ErrInvalidArgument, from, to)
	}
	t, ok := f.byID[projectID+"/"+tenantID]
	if !ok || t.Status != from {
		return false, nil
	}
	t.Status = to
	t.UpdatedAtMs++
	f.writes++
	return true, nil
}

// ListTenants mirrors the postgres store: it refuses a blank project or a
// limit below one, and returns newest first by (created, id), after
// q.After, at most q.Limit.
func (f *fakeTenantStore) ListTenants(_ context.Context, q TenantListQuery) ([]*Tenant, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if q.ProjectID == "" || q.Limit <= 0 {
		return nil, fmt.Errorf("%w: project_id and a positive limit are required", ErrInvalidArgument)
	}
	var out []*Tenant
	for _, t := range f.byID {
		if t.ProjectID != q.ProjectID {
			continue
		}
		if a := q.After; a != nil && (t.CreatedAtMs > a.CreatedAtMs || (t.CreatedAtMs == a.CreatedAtMs && t.ID >= a.ID)) {
			continue
		}
		cp := *t
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAtMs != out[j].CreatedAtMs {
			return out[i].CreatedAtMs > out[j].CreatedAtMs
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// CreateOwnedTenant mirrors the postgres store: the limit counts the
// owner's tenants created at or after WindowStartMs.
func (f *fakeTenantStore) CreateOwnedTenant(ctx context.Context, req OwnedTenantRequest) (*Tenant, *TenantMembership, error) {
	if f.createErr != nil {
		return nil, nil, f.createErr
	}
	created := 0
	for _, t := range f.byID {
		if t.ProjectID == req.ProjectID && t.CreatedBy == req.OwnerID && t.CreatedAtMs >= req.WindowStartMs {
			created++
		}
	}
	if created >= req.MaxPerWindow {
		return nil, nil, ErrTenantCreationLimited
	}
	f.nextID++
	now := time.Now().UnixMilli()
	t := &Tenant{
		ID: "tenant-owned-" + strconv.Itoa(f.nextID), ProjectID: req.ProjectID, Name: req.Name,
		Status: TenantStatusClaimed, CreatedBy: req.OwnerID, CreatedAtMs: now, UpdatedAtMs: now,
	}
	f.put(t)
	m := &TenantMembership{
		ProjectID: req.ProjectID, TenantID: t.ID, UserID: req.OwnerID,
		Source: MembershipSourceCreated, Role: RoleOwner, Status: MembershipStatusActive,
		CreatedAtMs: now, UpdatedAtMs: now,
	}
	if f.members != nil {
		id, err := f.members.UpsertMembership(ctx, m)
		if err != nil {
			return nil, nil, err
		}
		m.ID = id
	}
	return t, m, nil
}

var _ TenantStore = (*fakeTenantStore)(nil)

// fakeMembershipStore is an in-memory MembershipStore keyed by
// (projectID, tenantID, userID).
type fakeMembershipStore struct {
	byKey       map[string]*TenantMembership
	getErr      error
	upsertErr   error
	listErr     error
	transferErr error
	removedErr  error
	// tenants supplies each tenant's name and status to the active-tenant
	// reads (linkFakeTenantStores); unlinked, those reads find nothing.
	tenants *fakeTenantStore
	// accounts supplies the email RestoreMembership judges a domain
	// membership by, as the postgres store reads users.email_domain;
	// unlinked, or without the account, the email is "".
	accounts *fakeUserDirectory
	// onRestore runs as RestoreMembership starts, standing for a write that
	// lands between the service's checks and the restore's transaction.
	onRestore func()
	// verified holds each tenant's verified domains, keyed project/tenant,
	// for the active-tenant reads' domain rule (verifyDomain).
	verified map[string]map[string]bool
	// removed holds the memberships RemoveMembership recorded as removed and
	// no grant from another source has cleared, by key.
	removed map[string]bool
	// doorShut makes JoinByDomain find that the domain no longer lets anyone
	// join, as a SetDomainJoin(false) or a suspension landing between the
	// service's check and the write would.
	doorShut bool
}

// verifyDomain records domain as one tenantID has verified.
func (f *fakeMembershipStore) verifyDomain(projectID, tenantID, domain string) {
	if f.verified == nil {
		f.verified = map[string]map[string]bool{}
	}
	k := projectID + "/" + tenantID
	if f.verified[k] == nil {
		f.verified[k] = map[string]bool{}
	}
	f.verified[k][domain] = true
}

func newFakeMembershipStore() *fakeMembershipStore {
	return &fakeMembershipStore{byKey: map[string]*TenantMembership{}, removed: map[string]bool{}}
}

// clearRemoval mirrors the postgres store: a membership from any source but
// the email's domain lets a removed user back in.
func (f *fakeMembershipStore) clearRemoval(m *TenantMembership) {
	if m.Source != MembershipSourceDomain {
		delete(f.removed, f.key(m.ProjectID, m.TenantID, m.UserID))
	}
}

func (f *fakeMembershipStore) key(projectID, tenantID, userID string) string {
	return projectID + "/" + tenantID + "/" + userID
}

func (f *fakeMembershipStore) UpsertMembership(_ context.Context, m *TenantMembership) (string, error) {
	if f.upsertErr != nil {
		return "", f.upsertErr
	}
	f.clearRemoval(m)
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

// fakeRoleRank orders the roles as the postgres store does.
var fakeRoleRank = map[string]int{RoleOwner: 3, RoleAdmin: 2, RoleMember: 1}

// GrantMembership mirrors the postgres store: a suspended membership is
// ErrMemberSuspended and changes nothing; an active membership at the role
// or a higher one keeps its role; anything else becomes active at m.Role.
// Either way a membership keeps its source unless that is the domain's, and
// a grant from another source clears a removal.
func (f *fakeMembershipStore) GrantMembership(ctx context.Context, m *TenantMembership) (*TenantMembership, bool, error) {
	if f.upsertErr != nil {
		return nil, false, f.upsertErr
	}
	k := f.key(m.ProjectID, m.TenantID, m.UserID)
	if prior, ok := f.byKey[k]; ok && prior.Status == MembershipStatusSuspended {
		return nil, false, ErrMemberSuspended
	}
	f.clearRemoval(m)
	granted := *m
	granted.Status = MembershipStatusActive
	if prior, ok := f.byKey[k]; ok {
		granted.ID = prior.ID
		if prior.Status == MembershipStatusActive && fakeRoleRank[prior.Role] >= fakeRoleRank[m.Role] {
			if prior.Source != MembershipSourceDomain || m.Source == MembershipSourceDomain {
				out := *prior
				return &out, false, nil
			}
			granted.Role = prior.Role
		}
		if prior.Source != MembershipSourceDomain {
			granted.Source = prior.Source
		}
	}
	if _, err := f.UpsertMembership(ctx, &granted); err != nil {
		return nil, false, err
	}
	out, err := f.GetMembership(ctx, m.ProjectID, m.TenantID, m.UserID)
	return out, err == nil, err
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

// JoinByDomain mirrors the postgres store, with the domain's own rule left
// to the service's check unless doorShut says it has since closed: a removed
// user is ErrRemovedFromTenant, and otherwise it grants a domain member.
func (f *fakeMembershipStore) JoinByDomain(ctx context.Context, projectID, tenantID, userID, _ string) (*TenantMembership, bool, error) {
	if f.doorShut {
		return nil, false, nil
	}
	if f.removed[f.key(projectID, tenantID, userID)] {
		return nil, false, ErrRemovedFromTenant
	}
	return f.GrantMembership(ctx, &TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: userID,
		Source: MembershipSourceDomain, Role: RoleMember,
	})
}

func (f *fakeMembershipStore) IsRemoved(_ context.Context, projectID, tenantID, userID string) (bool, error) {
	if f.removedErr != nil {
		return false, f.removedErr
	}
	return f.removed[f.key(projectID, tenantID, userID)], nil
}

// RemoveMembership mirrors the postgres store: the tenant's last active
// owner is not removed (ErrLastOwner), and a removal is recorded.
func (f *fakeMembershipStore) RemoveMembership(_ context.Context, projectID, tenantID, userID string) (*TenantMembership, error) {
	k := f.key(projectID, tenantID, userID)
	target, ok := f.byKey[k]
	if !ok {
		return nil, nil
	}
	if err := f.keepAnOwner(target); err != nil {
		return nil, err
	}
	delete(f.byKey, k)
	f.removed[k] = true
	return target, nil
}

// keepAnOwner mirrors the postgres store's rule: target may not leave the
// tenant's active owners when it is the last of them (ErrLastOwner).
func (f *fakeMembershipStore) keepAnOwner(target *TenantMembership) error {
	if target.Role != RoleOwner || target.Status != MembershipStatusActive {
		return nil
	}
	for _, m := range f.byKey {
		if m.ProjectID == target.ProjectID && m.TenantID == target.TenantID && m.UserID != target.UserID &&
			m.Role == RoleOwner && m.Status == MembershipStatusActive {
			return nil
		}
	}
	return ErrLastOwner
}

// SuspendMembership mirrors the postgres store: an active membership is
// suspended unless it is the last active owner, a suspended one is returned
// unchanged, and anything else is ErrNotFound.
func (f *fakeMembershipStore) SuspendMembership(_ context.Context, projectID, tenantID, userID string) (*TenantMembership, bool, error) {
	target, ok := f.byKey[f.key(projectID, tenantID, userID)]
	switch {
	case !ok:
		return nil, false, ErrNotFound
	case target.Status == MembershipStatusSuspended:
		out := *target
		return &out, false, nil
	case target.Status != MembershipStatusActive:
		return nil, false, ErrNotFound
	}
	if err := f.keepAnOwner(target); err != nil {
		return nil, false, err
	}
	target.Status = MembershipStatusSuspended
	out := *target
	return &out, true, nil
}

// RestoreMembership mirrors the postgres store: by, unless an operator,
// must hold an active owner or admin membership, else
// ErrPermissionDenied; a suspended membership becomes active, or inactive
// when it is a domain one and the account's email is not on a domain the
// tenant verified; an active one is returned unchanged, and anything else
// is ErrNotFound.
func (f *fakeMembershipStore) RestoreMembership(_ context.Context, projectID, tenantID, userID string, restorer Restorer) (*TenantMembership, bool, error) {
	if f.onRestore != nil {
		f.onRestore()
	}
	if !restorer.IsOperator() {
		by := f.byKey[f.key(projectID, tenantID, restorer.UserID())]
		if by == nil || by.Status != MembershipStatusActive || !isAdminRole(by.Role) {
			return nil, false, ErrPermissionDenied
		}
	}
	target, ok := f.byKey[f.key(projectID, tenantID, userID)]
	switch {
	case !ok:
		return nil, false, ErrNotFound
	case target.Status == MembershipStatusActive:
		out := *target
		return &out, false, nil
	case target.Status != MembershipStatusSuspended:
		return nil, false, ErrNotFound
	}
	target.Status = MembershipStatusActive
	if target.Source == MembershipSourceDomain && !f.verified[projectID+"/"+tenantID][f.accountEmailDomain(projectID, userID)] {
		target.Status = MembershipStatusInactive
	}
	out := *target
	return &out, true, nil
}

// accountEmailDomain is the domain of the email of userID's account in
// accounts, as users.email_domain holds it, or "" for none.
func (f *fakeMembershipStore) accountEmailDomain(projectID, userID string) string {
	if f.accounts == nil {
		return ""
	}
	if u := f.accounts.byID[f.accounts.key(projectID, userID)]; u != nil {
		return emailDomain(FoldEmail(u.Email))
	}
	return ""
}

// TransferOwnership mirrors the postgres store's checks and writes.
func (f *fakeMembershipStore) TransferOwnership(_ context.Context, projectID, tenantID, fromUserID, toUserID string) (*TenantMembership, *TenantMembership, error) {
	if f.transferErr != nil {
		return nil, nil, f.transferErr
	}
	from, to := f.byKey[f.key(projectID, tenantID, fromUserID)], f.byKey[f.key(projectID, tenantID, toUserID)]
	if from == nil || from.Role != RoleOwner || from.Status != MembershipStatusActive {
		return nil, nil, ErrPermissionDenied
	}
	if to == nil || to.Status != MembershipStatusActive {
		return nil, nil, ErrNotFound
	}
	to.Role = RoleOwner
	if to.Source == MembershipSourceDomain {
		to.Source = MembershipSourceAdded
	}
	from.Role = RoleAdmin
	outFrom, outTo := *from, *to
	return &outFrom, &outTo, nil
}

// ListActiveTenantsForUser mirrors the postgres join: an active membership
// in a claimed tenant of the project, a domain one only on a domain the
// tenant verified, ordered by name, then id.
func (f *fakeMembershipStore) ListActiveTenantsForUser(_ context.Context, projectID, userID, emailDomain string) ([]*UserTenant, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []*UserTenant
	for _, m := range f.byKey {
		if ut := f.activeTenant(m, projectID, userID, emailDomain); ut != nil {
			out = append(out, ut)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out, nil
}

func (f *fakeMembershipStore) GetActiveTenantForUser(_ context.Context, projectID, tenantID, userID, emailDomain string) (*UserTenant, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	m, ok := f.byKey[f.key(projectID, tenantID, userID)]
	if !ok {
		return nil, nil
	}
	return f.activeTenant(m, projectID, userID, emailDomain), nil
}

func (f *fakeMembershipStore) activeTenant(m *TenantMembership, projectID, userID, emailDomain string) *UserTenant {
	if f.tenants == nil || m.ProjectID != projectID || m.UserID != userID || m.Status != MembershipStatusActive {
		return nil
	}
	if m.Source == MembershipSourceDomain && !f.verified[projectID+"/"+m.TenantID][emailDomain] {
		return nil
	}
	t, ok := f.tenants.byID[projectID+"/"+m.TenantID]
	if !ok || t.Status != TenantStatusClaimed {
		return nil
	}
	return &UserTenant{TenantID: t.ID, Name: t.Name, Role: m.Role, Source: m.Source}
}

var _ MembershipStore = (*fakeMembershipStore)(nil)

// fakeDNSResolver returns a fixed TXT record set (or error) per host.
// onLookup, when set, runs during the lookup, standing in for a write that
// lands while the check is in flight.
type fakeDNSResolver struct {
	records  map[string][]string
	err      error
	onLookup func()
}

func (f *fakeDNSResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	if f.onLookup != nil {
		f.onLookup()
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.records[host], nil
}

var _ DNSResolver = (*fakeDNSResolver)(nil)

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

// seedAdmin makes userID an active owner of (project, tenant), a claimed
// tenant unless the test put it in another status.
func (f *domainFixture) seedAdmin(projectID, tenantID, userID string) {
	f.tenants.ensure(projectID, tenantID)
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

	_, wantValue := dnsTXTChallenge(testProject, testTenant, testDomain)
	require.Equal(t, wantValue, out.TXTValue)
	require.Contains(t, out.TXTValue, domainVerifyTXTPrefix)

	// The challenge must be stable across calls and independent of the
	// caller's input casing.
	_, again := dnsTXTChallenge(testProject, testTenant, "ACME.COM")
	require.Equal(t, wantValue, again)

	// It names the tenant: another tenant's claim on the domain has its own.
	_, other := dnsTXTChallenge(testProject, "tenant-2", testDomain)
	require.NotEqual(t, wantValue, other)
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

	_, want := dnsTXTChallenge(testProject, testTenant, testDomain)
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

	_, want := dnsTXTChallenge(testProject, testTenant, testDomain)
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

	_, want := dnsTXTChallenge(testProject, testTenant, testDomain)
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

	_, want := dnsTXTChallenge(testProject, testTenant, testDomain)
	f.resolver.records[testDomain] = []string{want}

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

// Two tenants claim one domain. The record the domain's owner publishes is
// the owner's challenge, so it verifies the owner's claim and not the other
// tenant's; once verified, the other claim cannot verify at all.
func TestVerifyDomain_ContestedDomainVerifiesOnlyTheOwnersClaim(t *testing.T) {
	f := newDomainFixture()
	const squatter, squatterTenant = "user-squatter", "tenant-squatter"
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
	f.tenants.put(&Tenant{ID: squatterTenant, ProjectID: testProject, Status: TenantStatusClaimed})
	f.seedAdmin(testProject, testTenant, testCaller)
	f.seedAdmin(testProject, squatterTenant, squatter)
	squatID := f.seedPendingDomain(t, testProject, squatterTenant, testDomain)
	ownerID := f.seedPendingDomain(t, testProject, testTenant, testDomain)

	_, owners := dnsTXTChallenge(testProject, testTenant, testDomain)
	f.resolver.records[testDomain] = []string{owners}

	_, err := f.svc.VerifyDomain(withProject(testProject), squatter, squatID)
	require.ErrorIs(t, err, ErrPermissionDenied, "the owner's record is not the squatter's challenge")

	got, err := f.svc.VerifyDomain(withProject(testProject), testCaller, ownerID)
	require.NoError(t, err)
	require.Equal(t, DomainStatusVerified, got.Status)

	_, squatters := dnsTXTChallenge(testProject, squatterTenant, testDomain)
	f.resolver.records[testDomain] = []string{owners, squatters}
	_, err = f.svc.VerifyDomain(withProject(testProject), squatter, squatID)
	require.ErrorIs(t, err, ErrAlreadyExists, "a verified domain admits no second verification")
}

// A registration made before the challenge named the tenant still verifies
// with the project-wide value it was given; a registration made since does
// not.
func TestVerifyDomain_LegacyChallengeOnlyForLegacyRegistrations(t *testing.T) {
	_, legacy := legacyDNSTXTChallenge(testProject, testDomain)
	for name, tc := range map[string]struct {
		legacy bool
		want   error
	}{
		"legacy registration": {legacy: true},
		"new registration":    {legacy: false, want: ErrPermissionDenied},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDomainFixture()
			f.seedAdmin(testProject, testTenant, testCaller)
			f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusLatent})
			id := f.seedPendingDomain(t, testProject, testTenant, testDomain)
			f.domains.byID[f.domains.key(testProject, id)].LegacyTXTChallenge = tc.legacy
			f.resolver.records[testDomain] = []string{legacy}

			_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
		})
	}
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
	_, want := dnsTXTChallenge(testProject, testTenant, testDomain)
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
	_, want := dnsTXTChallenge(testProject, testTenant, testDomain)
	f.resolver.records[testDomain] = []string{want}
	f.tenants.setErr = errBoom

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, errBoom)
}

func TestVerifyDomain_PropagatesGrantMembershipError(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: TenantStatusClaimed})
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)
	_, want := dnsTXTChallenge(testProject, testTenant, testDomain)
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

// ── Governance writes and the attempt cap ──────────────────────────────

// publishedClaim seeds a tenant of the given status whose admin holds a
// pending dns_txt claim with its challenge published, and returns its id.
func (f *domainFixture) publishedClaim(t *testing.T, tenantStatus string) string {
	t.Helper()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.put(&Tenant{ID: testTenant, ProjectID: testProject, Status: tenantStatus})
	id := f.seedPendingDomain(t, testProject, testTenant, testDomain)
	_, want := dnsTXTChallenge(testProject, testTenant, testDomain)
	f.resolver.records[testDomain] = []string{want}
	return id
}

// Verifying a claim on a tenant that is already claimed writes the domain
// and leaves the tenant row alone; verifying it again writes nothing at all.
func TestVerifyDomain_WritesOnlyWhatChanges(t *testing.T) {
	f := newDomainFixture()
	id := f.publishedClaim(t, TenantStatusClaimed)
	ctx := withProject(testProject)

	_, err := f.svc.VerifyDomain(ctx, testCaller, id)
	require.NoError(t, err)
	require.Equal(t, 1, f.domains.writes)
	require.Zero(t, f.tenants.writes, "a claimed tenant is not claimed again")

	got, err := f.svc.VerifyDomain(ctx, testCaller, id)
	require.NoError(t, err)
	require.Equal(t, DomainStatusVerified, got.Status)
	require.Equal(t, 1, f.domains.writes, "re-verifying a verified domain writes nothing")
	require.Zero(t, f.tenants.writes)
	m, _ := f.members.GetMembership(context.Background(), testProject, testTenant, testCaller)
	require.Equal(t, RoleOwner, m.Role)
}

// A tenant suspended while its domain's check is in flight stays suspended:
// the verify claims the tenant only if it is still latent.
func TestVerifyDomain_SuspensionDuringTheCheckStands(t *testing.T) {
	f := newDomainFixture()
	id := f.publishedClaim(t, TenantStatusLatent)
	f.resolver.onLookup = func() {
		f.tenants.byID[testProject+"/"+testTenant].Status = TenantStatusSuspended
	}

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.NoError(t, err)
	tnt, _ := f.tenants.GetTenant(context.Background(), testProject, testTenant)
	require.Equal(t, TenantStatusSuspended, tnt.Status, "a claim never lifts a suspension")
}

// A failed re-check of a verified domain does not un-verify it; a failed
// check of a claim writes failed once, and a repeat of it writes nothing.
func TestVerifyDomain_FailedChecksWriteOnce(t *testing.T) {
	f := newDomainFixture()
	id := f.publishedClaim(t, TenantStatusClaimed)
	ctx := withProject(testProject)
	_, err := f.svc.VerifyDomain(ctx, testCaller, id)
	require.NoError(t, err)

	f.resolver.records[testDomain] = nil
	_, err = f.svc.VerifyDomain(ctx, testCaller, id)
	require.ErrorIs(t, err, ErrPermissionDenied)
	d, _ := f.domains.GetDomain(context.Background(), testProject, id)
	require.Equal(t, DomainStatusVerified, d.Status, "a lapsed record leaves the domain verified")
	require.Equal(t, 1, f.domains.writes)

	pending := f.seedPendingDomain(t, testProject, testTenant, "other.example.com")
	for range 2 {
		_, err = f.svc.VerifyDomain(ctx, testCaller, pending)
		require.ErrorIs(t, err, ErrPermissionDenied)
	}
	d, _ = f.domains.GetDomain(context.Background(), testProject, pending)
	require.Equal(t, DomainStatusFailed, d.Status)
	require.Equal(t, 2, f.domains.writes, "pending to failed is written once")
}

// A suspended tenant verifies nothing, and the refusal spends no attempt.
func TestVerifyDomain_SuspendedTenantSpendsNoAttempt(t *testing.T) {
	f := newDomainFixture()
	id := f.publishedClaim(t, TenantStatusSuspended)

	_, err := f.svc.VerifyDomain(withProject(testProject), testCaller, id)
	require.ErrorIs(t, err, ErrPermissionDenied)
	require.Empty(t, f.domains.attempts)
	require.Zero(t, f.domains.writes)
}

// Registrations and verifications share one per-tenant cap in a window; a
// refusal is logged and checks no DNS, and a refused caller spends nothing.
func TestDomainAttempts_CapRegistrationsAndVerifications(t *testing.T) {
	f := newDomainFixture()
	f.svc.cfg = &config.Config{TenantDomainAttemptsMaxPerTenant: 2, TenantDomainAttemptsWindowSeconds: 3600}
	core, logs := observer.New(zap.InfoLevel)
	f.svc.logger = zap.New(core)
	start := time.Now()
	f.svc.nowFunc = func() time.Time { return start }
	ctx := withProject(testProject)

	_, err := f.svc.CreateDomain(ctx, "user-stranger", testTenant, testDomain, DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrPermissionDenied)
	require.Empty(t, f.domains.attempts, "a refused caller spends no attempt")

	id := f.publishedClaim(t, TenantStatusLatent)
	f.resolver.records[testDomain] = nil
	_, err = f.svc.CreateDomain(ctx, testCaller, testTenant, "second.example.com", DomainVerificationDNSTXT)
	require.NoError(t, err)
	_, err = f.svc.VerifyDomain(ctx, testCaller, id)
	require.ErrorIs(t, err, ErrPermissionDenied)

	_, want := dnsTXTChallenge(testProject, testTenant, testDomain)
	f.resolver.records[testDomain] = []string{want}
	_, err = f.svc.VerifyDomain(ctx, testCaller, id)
	require.ErrorIs(t, err, ErrDomainAttemptsLimited)
	d, _ := f.domains.GetDomain(context.Background(), testProject, id)
	require.Equal(t, DomainStatusFailed, d.Status, "a refused attempt checks nothing")
	_, err = f.svc.CreateDomain(ctx, testCaller, testTenant, "third.example.com", DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrDomainAttemptsLimited)
	list, _ := f.domains.ListDomainsByTenant(context.Background(), testProject, testTenant)
	require.Len(t, list, 2, "a refused registration writes nothing")

	entries := logs.FilterMessage("tenant_domain_attempts_limited").All()
	require.Len(t, entries, 2)
	require.Equal(t, testTenant, entries[0].ContextMap()["tenant_id"])

	f.svc.nowFunc = func() time.Time { return start.Add(time.Hour + time.Second) }
	_, err = f.svc.VerifyDomain(ctx, testCaller, id)
	require.NoError(t, err, "the window has moved on")
}

func TestDomainAttempts_PropagatesStoreError(t *testing.T) {
	f := newDomainFixture()
	id := f.publishedClaim(t, TenantStatusLatent)
	f.domains.attemptErr = errBoom
	ctx := withProject(testProject)

	_, err := f.svc.VerifyDomain(ctx, testCaller, id)
	require.ErrorIs(t, err, errBoom)
	_, err = f.svc.CreateDomain(ctx, testCaller, testTenant, "second.example.com", DomainVerificationDNSTXT)
	require.ErrorIs(t, err, errBoom)
	d, _ := f.domains.GetDomain(context.Background(), testProject, id)
	require.Equal(t, DomainStatusPending, d.Status)
}

// A suspended tenant's admins can neither register nor list its domains,
// and a refused registration spends no attempt.
func TestDomainRPCs_SuspendedTenantRefusesItsAdmins(t *testing.T) {
	f := newDomainFixture()
	f.seedAdmin(testProject, testTenant, testCaller)
	f.tenants.byID[testProject+"/"+testTenant].Status = TenantStatusSuspended
	ctx := withProject(testProject)

	_, err := f.svc.CreateDomain(ctx, testCaller, testTenant, testDomain, DomainVerificationDNSTXT)
	require.ErrorIs(t, err, ErrPermissionDenied)
	_, err = f.svc.ListTenantDomains(ctx, testCaller, testTenant)
	require.ErrorIs(t, err, ErrPermissionDenied)
	require.Empty(t, f.domains.attempts)
	require.Zero(t, f.domains.writes)
}
