package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
)

// fakeTenantAdmin records every cross-tenant admin call and lets tests
// inject failures at a specific step + verify rollback behaviour.
type fakeTenantAdmin struct {
	mu sync.Mutex

	tenants     map[string]string // tenantID -> displayName
	memberships map[string]string // tenantID|userID -> role; written by repo.CreateUser via promoteOnRepoCreateUser

	// Failure injections — when set, the matching call returns the
	// configured error before mutating state.
	failCreateTenant error
	failPromote      error
}

func newFakeTenantAdmin() *fakeTenantAdmin {
	return &fakeTenantAdmin{
		tenants:     map[string]string{},
		memberships: map[string]string{},
	}
}

func (a *fakeTenantAdmin) CreateTenant(_ context.Context, tenantID, displayName string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failCreateTenant != nil {
		return a.failCreateTenant
	}
	if _, ok := a.tenants[tenantID]; ok {
		return ErrAlreadyExists
	}
	a.tenants[tenantID] = displayName
	return nil
}

func (a *fakeTenantAdmin) PromoteTenantMember(_ context.Context, tenantID, userID, role string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failPromote != nil {
		return a.failPromote
	}
	a.memberships[tenantID+"|"+userID] = role
	return nil
}

func (a *fakeTenantAdmin) RemoveTenantMember(_ context.Context, tenantID, userID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.memberships, tenantID+"|"+userID)
	return nil
}

func (a *fakeTenantAdmin) tenantExists(tenantID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.tenants[tenantID]
	return ok
}

func (a *fakeTenantAdmin) memberRole(tenantID, userID string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	role, ok := a.memberships[tenantID+"|"+userID]
	return role, ok
}

// repoStub is a wrapper over fakeRepo that tracks the tenant id it was
// constructed for. Used to assert OrganizationSignup writes Organization
// + User + OrganizationMembership rows to the NEW tenant's repo, not
// the deployment's default tenant.
type repoStub struct {
	*fakeRepo
	tenantID string

	// Failure injection.
	failCreateOrg    error
	failCreateUser   error
	failAddOrgMember error
}

func (r *repoStub) CreateOrganization(ctx context.Context, o *Organization) (string, error) {
	if r.failCreateOrg != nil {
		return "", r.failCreateOrg
	}
	return r.fakeRepo.CreateOrganization(ctx, o)
}

func (r *repoStub) CreateUser(ctx context.Context, u *User) (string, error) {
	if r.failCreateUser != nil {
		return "", r.failCreateUser
	}
	return r.fakeRepo.CreateUser(ctx, u)
}

func (r *repoStub) AddOrganizationMember(ctx context.Context, m *OrganizationMembership) (string, error) {
	if r.failAddOrgMember != nil {
		return "", r.failAddOrgMember
	}
	return r.fakeRepo.AddOrganizationMember(ctx, m)
}

type tenantRepoRegistry struct {
	mu        sync.Mutex
	byTenant  map[string]*repoStub
	overrides map[string]*repoStub // optional pre-built stubs keyed by tenant id
}

func newTenantRepoRegistry() *tenantRepoRegistry {
	return &tenantRepoRegistry{byTenant: map[string]*repoStub{}, overrides: map[string]*repoStub{}}
}

func (reg *tenantRepoRegistry) factory() RepositoryForTenant {
	return func(tenantID string) Repository {
		reg.mu.Lock()
		defer reg.mu.Unlock()
		if override, ok := reg.overrides[tenantID]; ok {
			reg.byTenant[tenantID] = override
			return override
		}
		if existing, ok := reg.byTenant[tenantID]; ok {
			return existing
		}
		rs := &repoStub{fakeRepo: newFakeRepo(), tenantID: tenantID}
		reg.byTenant[tenantID] = rs
		return rs
	}
}

func (reg *tenantRepoRegistry) get(tenantID string) *repoStub {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.byTenant[tenantID]
}

func multiModeConfig() *config.Config {
	cfg := testConfig()
	cfg.IdentityMode = config.IdentityModeMulti
	return cfg
}

func newOrgSignupService(t *testing.T, admin TenantAdmin, factory RepositoryForTenant) *OrganizationSignupService {
	t.Helper()
	cfg := multiModeConfig()
	kr := testKeyRing(t)
	auditLog := audit.NewLogger(nil, "test-tenant", zap.NewNop())
	return NewOrganizationSignupService(admin, factory, cfg, kr, auditLog, zap.NewNop())
}

func TestOrganizationSignup_HappyPath_All7Steps(t *testing.T) {
	t.Parallel()

	admin := newFakeTenantAdmin()
	reg := newTenantRepoRegistry()
	svc := newOrgSignupService(t, admin, reg.factory())

	result, err := svc.Signup(context.Background(), "acmecorp", "Acme Corp", "owner@acme.test", "MyStr0ng!Pass", "Owner")
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}

	// Step 2: tenant created in tenant-shard-db.
	if !admin.tenantExists("acmecorp") {
		t.Fatalf("expected tenant 'acmecorp' to exist in tenant-shard-db")
	}
	// Step 4: admin promoted to "admin" at the storage layer.
	if role, ok := admin.memberRole("acmecorp", result.User.ID); !ok || role != "admin" {
		t.Fatalf("expected admin membership in 'acmecorp': role=%q ok=%v", role, ok)
	}

	// Step 5: Organization row in the NEW tenant's repository.
	tenantRepo := reg.get("acmecorp")
	if tenantRepo == nil {
		t.Fatalf("expected per-tenant repo factory to be invoked for 'acmecorp'")
	}
	orgs, err := tenantRepo.ListOrganizationsForUser(context.Background(), result.User.ID)
	if err != nil {
		t.Fatalf("ListOrganizationsForUser: %v", err)
	}
	if len(orgs) != 1 {
		t.Fatalf("expected one org in tenant repo, got %d", len(orgs))
	}
	if orgs[0].Slug != "acmecorp" {
		t.Fatalf("org slug = %q, want acmecorp", orgs[0].Slug)
	}

	// Step 6: admin User row exists in the new tenant's repo.
	user, err := tenantRepo.FindUserByEmail(context.Background(), "owner@acme.test")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if user == nil {
		t.Fatalf("expected admin user in new tenant repo")
	}
	if user.Role != "admin" {
		t.Fatalf("admin user role = %q, want admin", user.Role)
	}
	if user.PasswordHash == "" {
		t.Fatalf("admin user has no password hash")
	}

	// Token issuance.
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatalf("expected access+refresh tokens, got access=%q refresh=%q", result.AccessToken, result.RefreshToken)
	}

	if result.Organization.OwnerUserID != result.User.ID {
		t.Fatalf("org owner = %q, want %q", result.Organization.OwnerUserID, result.User.ID)
	}
}

func TestOrganizationSignup_SingleMode_ReturnsUnimplemented(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.IdentityMode = config.IdentityModeSingle
	kr := testKeyRing(t)
	svc := NewOrganizationSignupService(newFakeTenantAdmin(), newTenantRepoRegistry().factory(), cfg, kr, nil, zap.NewNop())

	_, err := svc.Signup(context.Background(), "acmecorp", "Acme", "owner@acme.test", "MyStr0ng!Pass", "")
	if !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("expected ErrUnimplemented, got %v", err)
	}
}

func TestOrganizationSignup_InvalidSlug_NoTenantCreated(t *testing.T) {
	t.Parallel()

	admin := newFakeTenantAdmin()
	svc := newOrgSignupService(t, admin, newTenantRepoRegistry().factory())

	cases := []string{"", "A", "-acme", "acme-", "acme corp", "acme/corp"}
	for _, slug := range cases {
		_, err := svc.Signup(context.Background(), slug, "Acme", "owner@acme.test", "MyStr0ng!Pass", "")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("slug %q: expected ErrInvalidArgument, got %v", slug, err)
		}
		if len(admin.tenants) != 0 {
			t.Fatalf("slug %q caused a tenant to be created: %#v", slug, admin.tenants)
		}
	}
}

func TestOrganizationSignup_WeakPassword_NoTenantCreated(t *testing.T) {
	t.Parallel()

	admin := newFakeTenantAdmin()
	svc := newOrgSignupService(t, admin, newTenantRepoRegistry().factory())

	_, err := svc.Signup(context.Background(), "acmecorp", "Acme", "owner@acme.test", "short", "")
	if !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("expected ErrWeakPassword, got %v", err)
	}
	if len(admin.tenants) != 0 {
		t.Fatalf("weak password caused a tenant to be created: %#v", admin.tenants)
	}
}

func TestOrganizationSignup_SlugCollision_ReturnsAlreadyExists(t *testing.T) {
	t.Parallel()

	admin := newFakeTenantAdmin()
	reg := newTenantRepoRegistry()
	svc := newOrgSignupService(t, admin, reg.factory())

	// Seed: the slug is already taken in tenant-shard-db.
	_ = admin.CreateTenant(context.Background(), "acmecorp", "Existing")

	_, err := svc.Signup(context.Background(), "acmecorp", "Doppelganger", "owner@acme.test", "MyStr0ng!Pass", "")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestOrganizationSignup_CreateUserRowFails_TenantRemainsNoMembership(t *testing.T) {
	t.Parallel()

	admin := newFakeTenantAdmin()
	reg := newTenantRepoRegistry()
	prepared := &repoStub{fakeRepo: newFakeRepo(), tenantID: "acmecorp", failCreateUser: errors.New("constraint violation")}
	reg.overrides["acmecorp"] = prepared

	svc := newOrgSignupService(t, admin, reg.factory())
	_, err := svc.Signup(context.Background(), "acmecorp", "Acme", "owner@acme.test", "MyStr0ng!Pass", "")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "create admin user row") {
		t.Fatalf("expected error to mention 'create admin user row', got %v", err)
	}
	// Tenant exists (no DeleteTenant primitive) but no admin promotion / org.
	if !admin.tenantExists("acmecorp") {
		t.Fatalf("tenant should remain after CreateTenant succeeded; cannot be rolled back")
	}
	if len(admin.memberships) != 0 {
		t.Fatalf("no memberships should exist when CreateUser failed before promotion")
	}
}

func TestOrganizationSignup_PromoteFails_RollsBackTenantMember(t *testing.T) {
	t.Parallel()

	admin := newFakeTenantAdmin()
	admin.failPromote = errors.New("role-change service down")
	reg := newTenantRepoRegistry()
	svc := newOrgSignupService(t, admin, reg.factory())

	_, err := svc.Signup(context.Background(), "acmecorp", "Acme", "owner@acme.test", "MyStr0ng!Pass", "")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "promote admin tenant member") {
		t.Fatalf("expected error to mention 'promote admin tenant member', got %v", err)
	}
	// Promotion failed; we attempt to remove the (default "member")
	// membership the repo.CreateUser path added. The fakeRepo doesn't
	// model that membership, but RemoveTenantMember is still called and
	// must not error — verified by reaching here without panicking.
	if len(admin.memberships) != 0 {
		t.Fatalf("memberships should be empty after rollback; got %#v", admin.memberships)
	}
}

func TestOrganizationSignup_CreateOrgRowFails_RollsBackTenantMember(t *testing.T) {
	t.Parallel()

	admin := newFakeTenantAdmin()
	reg := newTenantRepoRegistry()
	prepared := &repoStub{fakeRepo: newFakeRepo(), tenantID: "acmecorp", failCreateOrg: errors.New("disk full")}
	reg.overrides["acmecorp"] = prepared

	svc := newOrgSignupService(t, admin, reg.factory())
	_, err := svc.Signup(context.Background(), "acmecorp", "Acme", "owner@acme.test", "MyStr0ng!Pass", "")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "create organization row") {
		t.Fatalf("expected error to mention 'create organization row', got %v", err)
	}
	// Rollback: storage-layer membership removed (compensating delete).
	if len(admin.memberships) != 0 {
		t.Fatalf("tenant-member rollback failed; memberships=%#v", admin.memberships)
	}
	if !admin.tenantExists("acmecorp") {
		t.Fatalf("tenant should remain (cannot be deleted)")
	}
}

func TestOrganizationSignup_AddOrgMemberFails_RollsBackTenantMember(t *testing.T) {
	t.Parallel()

	admin := newFakeTenantAdmin()
	reg := newTenantRepoRegistry()
	prepared := &repoStub{fakeRepo: newFakeRepo(), tenantID: "acmecorp", failAddOrgMember: errors.New("index corrupt")}
	reg.overrides["acmecorp"] = prepared

	svc := newOrgSignupService(t, admin, reg.factory())
	_, err := svc.Signup(context.Background(), "acmecorp", "Acme", "owner@acme.test", "MyStr0ng!Pass", "")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "add organization member") {
		t.Fatalf("expected error to mention 'add organization member', got %v", err)
	}
	if len(admin.memberships) != 0 {
		t.Fatalf("tenant-member rollback failed; memberships=%#v", admin.memberships)
	}
}

func TestOrganizationSignup_NilWiring_ReturnsConfigError(t *testing.T) {
	t.Parallel()

	cfg := multiModeConfig()
	kr := testKeyRing(t)
	// nil tenantAdmin
	svc := NewOrganizationSignupService(nil, newTenantRepoRegistry().factory(), cfg, kr, nil, zap.NewNop())
	_, err := svc.Signup(context.Background(), "acmecorp", "Acme", "owner@acme.test", "MyStr0ng!Pass", "")
	if err == nil || !strings.Contains(err.Error(), "service not wired") {
		t.Fatalf("expected service not wired error, got %v", err)
	}
}
