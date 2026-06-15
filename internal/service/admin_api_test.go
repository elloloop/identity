package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/elloloop/identity/pkg/passwords"
)

// fakeControlPlaneStore is an in-memory ControlPlaneProjectStore. It reuses
// the same nil-on-miss conventions as the real postgres store and records
// what it was handed so the credential-hashing and auth-domain seeding can be
// asserted without a database.
type fakeControlPlaneStore struct {
	projects    map[string]*AdminProject
	credentials map[string]*AdminProjectCredential
	authDomains map[string]string // hostname → projectID
	createErr   error
	credErr     error
	domainErr   error
	nextID      int
	lastDomain  struct {
		projectID    string
		hostname     string
		isPrimary    bool
		verifiedAtMs int64
	}
}

func newFakeControlPlaneStore() *fakeControlPlaneStore {
	return &fakeControlPlaneStore{
		projects:    map[string]*AdminProject{},
		credentials: map[string]*AdminProjectCredential{},
		authDomains: map[string]string{},
	}
}

func (f *fakeControlPlaneStore) id(prefix string) string {
	f.nextID++
	return prefix + "-" + strings.Repeat("0", 0) + itoa(f.nextID)
}

func (f *fakeControlPlaneStore) CreateProject(_ context.Context, p *AdminProject) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	id := p.ID
	if id == "" {
		id = f.id("proj")
	}
	cp := *p
	cp.ID = id
	f.projects[id] = &cp
	p.ID = id
	return id, nil
}

func (f *fakeControlPlaneStore) CreateProjectCredential(_ context.Context, c *AdminProjectCredential) (string, error) {
	if f.credErr != nil {
		return "", f.credErr
	}
	id := c.ID
	if id == "" {
		id = f.id("cred")
	}
	cp := *c
	cp.ID = id
	f.credentials[id] = &cp
	c.ID = id
	return id, nil
}

func (f *fakeControlPlaneStore) EnsureAuthDomain(_ context.Context, projectID, hostname string, isPrimary bool, verifiedAtMs int64) error {
	if f.domainErr != nil {
		return f.domainErr
	}
	if owner, ok := f.authDomains[hostname]; ok && owner != projectID {
		return ErrAlreadyExists
	}
	f.authDomains[hostname] = projectID
	f.lastDomain.projectID = projectID
	f.lastDomain.hostname = hostname
	f.lastDomain.isPrimary = isPrimary
	f.lastDomain.verifiedAtMs = verifiedAtMs
	return nil
}

var _ ControlPlaneProjectStore = (*fakeControlPlaneStore)(nil)

// itoa avoids importing strconv just for the fake's id minting.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

const testAdminSecret = "s3cr3t-operator-key"

// fakePlatformAdminStore is an in-memory PlatformAdminStore. It enforces the
// "first admin only" contract the postgres store provides via an advisory
// lock: the first successful CreateFirstPlatformAdmin inserts and reports
// created=true; every later one reports created=false. A mutex makes the
// check-then-insert atomic so the concurrency test exercises real serialization.
type fakePlatformAdminStore struct {
	mu        sync.Mutex
	admins    []*PlatformAdmin
	createErr error
	nextID    int
}

func newFakePlatformAdminStore() *fakePlatformAdminStore {
	return &fakePlatformAdminStore{}
}

func (f *fakePlatformAdminStore) CreateFirstPlatformAdmin(_ context.Context, a *PlatformAdmin) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return false, f.createErr
	}
	if len(f.admins) > 0 {
		return false, nil
	}
	f.nextID++
	if a.ID == "" {
		a.ID = "admin-" + itoa(f.nextID)
	}
	cp := *a
	f.admins = append(f.admins, &cp)
	return true, nil
}

func (f *fakePlatformAdminStore) CountPlatformAdmins(_ context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.admins), nil
}

var _ PlatformAdminStore = (*fakePlatformAdminStore)(nil)

type adminFixture struct {
	svc      *ControlPlaneAdminService
	projects *fakeControlPlaneStore
	tenants  *fakeTenantStore
	members  *fakeMembershipStore
	admins   *fakePlatformAdminStore
}

func newAdminFixture(secret string) *adminFixture {
	p := newFakeControlPlaneStore()
	t := newFakeTenantStore()
	m := newFakeMembershipStore()
	a := newFakePlatformAdminStore()
	return &adminFixture{
		svc:      NewControlPlaneAdminService(secret, p, t, m, a, nil),
		projects: p,
		tenants:  t,
		members:  m,
		admins:   a,
	}
}

// ── secret empty → every RPC is Unimplemented ────────────────────────────

func TestControlPlaneAdmin_DisabledWhenSecretEmpty(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	ctx := context.Background()

	if f.svc.Enabled() {
		t.Fatal("Enabled() = true with empty secret, want false")
	}

	// Even presenting *some* secret cannot enable a disabled surface.
	if _, err := f.svc.AdminCreateProject(ctx, "anything", "p", "scope"); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("AdminCreateProject: err = %v, want ErrUnimplemented", err)
	}
	if _, err := f.svc.AdminCreateProjectCredential(ctx, "anything", "proj", CredentialKindSecret); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("AdminCreateProjectCredential: err = %v, want ErrUnimplemented", err)
	}
	if err := f.svc.AdminAddProjectAuthDomain(ctx, "anything", "proj", "h.example.com", true); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("AdminAddProjectAuthDomain: err = %v, want ErrUnimplemented", err)
	}
	if _, err := f.svc.AdminCreateTenant(ctx, "anything", "proj", "Acme", "acme.com"); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("AdminCreateTenant: err = %v, want ErrUnimplemented", err)
	}
	if _, err := f.svc.AdminAddTenantAdmin(ctx, "anything", "proj", "t", "u", RoleOwner); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("AdminAddTenantAdmin: err = %v, want ErrUnimplemented", err)
	}

	// Nothing must have been written.
	if len(f.projects.projects) != 0 || len(f.tenants.byID) != 0 || len(f.members.byKey) != 0 {
		t.Fatal("disabled surface must not write anything")
	}
}

// ── wrong / missing secret → PermissionDenied ────────────────────────────

func TestControlPlaneAdmin_WrongOrMissingSecretDenied(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	if !f.svc.Enabled() {
		t.Fatal("Enabled() = false with a configured secret, want true")
	}

	for _, presented := range []string{"", "wrong", testAdminSecret + "x", strings.ToUpper(testAdminSecret)} {
		if _, err := f.svc.AdminCreateProject(ctx, presented, "p", "scope"); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("AdminCreateProject(secret=%q): err = %v, want ErrPermissionDenied", presented, err)
		}
		if _, err := f.svc.AdminCreateProjectCredential(ctx, presented, "proj", CredentialKindSecret); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("AdminCreateProjectCredential(secret=%q): err = %v, want ErrPermissionDenied", presented, err)
		}
		if err := f.svc.AdminAddProjectAuthDomain(ctx, presented, "proj", "h.example.com", false); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("AdminAddProjectAuthDomain(secret=%q): err = %v, want ErrPermissionDenied", presented, err)
		}
		if _, err := f.svc.AdminCreateTenant(ctx, presented, "proj", "Acme", "acme.com"); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("AdminCreateTenant(secret=%q): err = %v, want ErrPermissionDenied", presented, err)
		}
		if _, err := f.svc.AdminAddTenantAdmin(ctx, presented, "proj", "t", "u", RoleOwner); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("AdminAddTenantAdmin(secret=%q): err = %v, want ErrPermissionDenied", presented, err)
		}
	}

	if len(f.projects.projects) != 0 || len(f.tenants.byID) != 0 || len(f.members.byKey) != 0 {
		t.Fatal("denied calls must not write anything")
	}
}

// ── correct secret → each RPC succeeds ───────────────────────────────────

func TestControlPlaneAdmin_CreateProject(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	id, err := f.svc.AdminCreateProject(ctx, testAdminSecret, "  Acme  ", "  scope-1  ")
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	stored := f.projects.projects[id]
	if stored == nil {
		t.Fatalf("project %q not stored", id)
	}
	if stored.StorageScopeID != "scope-1" || stored.Name != "Acme" {
		t.Fatalf("stored project = %+v (storage scope/name not trimmed)", stored)
	}
}

func TestControlPlaneAdmin_CreateProject_RequiresStorageScope(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	if _, err := f.svc.AdminCreateProject(context.Background(), testAdminSecret, "Acme", "   "); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank storage scope: err = %v, want ErrInvalidArgument", err)
	}
}

func TestControlPlaneAdmin_CreateSecretCredential_ReturnsRawKeyOnce(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	got, err := f.svc.AdminCreateProjectCredential(ctx, testAdminSecret, "proj-1", CredentialKindSecret)
	if err != nil {
		t.Fatalf("AdminCreateProjectCredential: %v", err)
	}
	if got.RawKey == "" {
		t.Fatal("secret credential must return a raw key once")
	}
	if !strings.HasPrefix(got.PublicID, secretKeyPrefix) {
		t.Fatalf("public id %q lacks the secret-key prefix %q", got.PublicID, secretKeyPrefix)
	}
	// The raw key is publicID.secret — the public-id half must match.
	if !strings.HasPrefix(got.RawKey, got.PublicID+".") {
		t.Fatalf("raw key %q does not embed public id %q", got.RawKey, got.PublicID)
	}
	rawSecret := strings.TrimPrefix(got.RawKey, got.PublicID+".")

	stored := f.projects.credentials[got.ID]
	if stored == nil {
		t.Fatalf("credential %q not stored", got.ID)
	}
	// Only the HASH of the secret is persisted — never the raw secret.
	if stored.SecretHash == "" || stored.SecretHash == rawSecret {
		t.Fatalf("secret hash must be a hash of the raw secret, got %q (raw %q)", stored.SecretHash, rawSecret)
	}
	if stored.SecretHash != sha256Hex(rawSecret) {
		t.Fatal("stored hash is not sha256 of the raw secret")
	}
	if strings.Contains(stored.PublicID, rawSecret) {
		t.Fatal("raw secret must not appear in the stored public id")
	}
}

func TestControlPlaneAdmin_CreatePublishableCredential_NoSecret(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	// Default (blank) kind is publishable.
	got, err := f.svc.AdminCreateProjectCredential(ctx, testAdminSecret, "proj-1", "")
	if err != nil {
		t.Fatalf("AdminCreateProjectCredential: %v", err)
	}
	if got.RawKey != "" {
		t.Fatalf("publishable credential must have no raw key, got %q", got.RawKey)
	}
	if !strings.HasPrefix(got.PublicID, publishableKeyPrefix) {
		t.Fatalf("public id %q lacks publishable prefix %q", got.PublicID, publishableKeyPrefix)
	}
	stored := f.projects.credentials[got.ID]
	if stored == nil || stored.Kind != CredentialKindPublishable || stored.SecretHash != "" {
		t.Fatalf("stored publishable credential = %+v", stored)
	}
}

func TestControlPlaneAdmin_CreateCredential_UnknownKindRejected(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	if _, err := f.svc.AdminCreateProjectCredential(context.Background(), testAdminSecret, "proj", "mtls"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("unknown kind: err = %v, want ErrInvalidArgument", err)
	}
}

func TestControlPlaneAdmin_CreateCredential_RequiresProjectID(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	if _, err := f.svc.AdminCreateProjectCredential(context.Background(), testAdminSecret, "  ", CredentialKindSecret); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank project id: err = %v, want ErrInvalidArgument", err)
	}
}

func TestControlPlaneAdmin_AddAuthDomain_SeededVerified(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	before := f.svc.nowFunc()
	if err := f.svc.AdminAddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "  Auth.Acme.COM ", true); err != nil {
		t.Fatalf("AdminAddProjectAuthDomain: %v", err)
	}
	d := f.projects.lastDomain
	if d.projectID != "proj-1" || d.hostname != "auth.acme.com" {
		t.Fatalf("auth domain = %+v (hostname not normalized)", d)
	}
	if !d.isPrimary {
		t.Fatal("is_primary not propagated")
	}
	if d.verifiedAtMs < before {
		t.Fatalf("verified_at_ms %d should be >= %d (operator-asserted, seeded verified)", d.verifiedAtMs, before)
	}
}

func TestControlPlaneAdmin_AddAuthDomain_RequiresHostname(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	if err := f.svc.AdminAddProjectAuthDomain(context.Background(), testAdminSecret, "proj", "  ", false); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank hostname: err = %v, want ErrInvalidArgument", err)
	}
}

func TestControlPlaneAdmin_AddAuthDomain_RequiresProjectID(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	if err := f.svc.AdminAddProjectAuthDomain(context.Background(), testAdminSecret, "   ", "h.example.com", false); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank project id: err = %v, want ErrInvalidArgument", err)
	}
}

func TestControlPlaneAdmin_CreateTenant_ClaimedAndNormalized(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	id, err := f.svc.AdminCreateTenant(ctx, testAdminSecret, "proj-1", "  Acme Inc  ", "  Acme.COM ")
	if err != nil {
		t.Fatalf("AdminCreateTenant: %v", err)
	}
	stored := f.tenants.byID["proj-1/"+id]
	if stored == nil {
		t.Fatalf("tenant %q not stored under project proj-1", id)
	}
	if stored.Status != TenantStatusClaimed {
		t.Fatalf("operator-created tenant status = %q, want %q", stored.Status, TenantStatusClaimed)
	}
	if stored.Name != "Acme Inc" || stored.PrimaryDomain != "acme.com" {
		t.Fatalf("tenant fields not normalized: %+v", stored)
	}
}

func TestControlPlaneAdmin_CreateTenant_RequiresProjectID(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	if _, err := f.svc.AdminCreateTenant(context.Background(), testAdminSecret, "  ", "Acme", "acme.com"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank project id: err = %v, want ErrInvalidArgument", err)
	}
}

func TestControlPlaneAdmin_AddTenantAdmin_DefaultsOwner(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	m, err := f.svc.AdminAddTenantAdmin(ctx, testAdminSecret, "proj-1", "tenant-1", "user-1", "")
	if err != nil {
		t.Fatalf("AdminAddTenantAdmin: %v", err)
	}
	if m.Role != RoleOwner || m.Source != MembershipSourceAdded || m.Status != MembershipStatusActive {
		t.Fatalf("membership = %+v, want owner/added/active", m)
	}
	stored, _ := f.members.GetMembership(ctx, "proj-1", "tenant-1", "user-1")
	if stored == nil || stored.Role != RoleOwner {
		t.Fatalf("stored membership = %+v", stored)
	}
}

func TestControlPlaneAdmin_AddTenantAdmin_AdminRoleAllowed(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	m, err := f.svc.AdminAddTenantAdmin(context.Background(), testAdminSecret, "p", "t", "u", "ADMIN")
	if err != nil {
		t.Fatalf("AdminAddTenantAdmin(admin): %v", err)
	}
	if m.Role != RoleAdmin {
		t.Fatalf("role = %q, want %q", m.Role, RoleAdmin)
	}
}

func TestControlPlaneAdmin_AddTenantAdmin_RejectsMemberRole(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	if _, err := f.svc.AdminAddTenantAdmin(context.Background(), testAdminSecret, "p", "t", "u", RoleMember); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("member role: err = %v, want ErrInvalidArgument (bootstraps administration only)", err)
	}
}

func TestControlPlaneAdmin_AddTenantAdmin_RequiresIDs(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()
	cases := []struct{ projectID, tenantID, userID string }{
		{"", "t", "u"},
		{"p", "", "u"},
		{"p", "t", ""},
	}
	for _, c := range cases {
		if _, err := f.svc.AdminAddTenantAdmin(ctx, testAdminSecret, c.projectID, c.tenantID, c.userID, RoleOwner); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("ids %+v: err = %v, want ErrInvalidArgument", c, err)
		}
	}
}

// ── store errors propagate (after a successful auth) ─────────────────────

func TestControlPlaneAdmin_StoreErrorsPropagate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	wantErr := errors.New("boom")

	t.Run("create project", func(t *testing.T) {
		f := newAdminFixture(testAdminSecret)
		f.projects.createErr = wantErr
		if _, err := f.svc.AdminCreateProject(ctx, testAdminSecret, "n", "scope"); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v, want %v", err, wantErr)
		}
	})
	t.Run("create credential", func(t *testing.T) {
		f := newAdminFixture(testAdminSecret)
		f.projects.credErr = wantErr
		if _, err := f.svc.AdminCreateProjectCredential(ctx, testAdminSecret, "proj", CredentialKindSecret); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v, want %v", err, wantErr)
		}
	})
	t.Run("add auth domain", func(t *testing.T) {
		f := newAdminFixture(testAdminSecret)
		f.projects.domainErr = wantErr
		if err := f.svc.AdminAddProjectAuthDomain(ctx, testAdminSecret, "proj", "h.example.com", false); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v, want %v", err, wantErr)
		}
	})
	t.Run("add tenant admin", func(t *testing.T) {
		f := newAdminFixture(testAdminSecret)
		f.members.upsertErr = wantErr
		if _, err := f.svc.AdminAddTenantAdmin(ctx, testAdminSecret, "p", "t", "u", RoleOwner); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v, want %v", err, wantErr)
		}
	})
	t.Run("create first platform admin", func(t *testing.T) {
		f := newAdminFixture(testAdminSecret)
		f.admins.createErr = wantErr
		if _, err := f.svc.CreateFirstPlatformAdmin(ctx, "ops@acme.com", "Str0ng!Bootstrap"); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v, want %v", err, wantErr)
		}
	})
}

// ── zero-config first-admin bootstrap ────────────────────────────────────

// The bootstrap is the ONE admin RPC that is NOT secret-gated: a fresh
// deployer has configured no secret yet. These tests use a service built with
// an EMPTY secret to prove the surface still works.

func TestCreateFirstPlatformAdmin_EmptyTableCreatesAdmin(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("") // empty secret: the rest of the surface is disabled
	ctx := context.Background()

	got, err := f.svc.CreateFirstPlatformAdmin(ctx, "  Ops@Acme.com ", "")
	if err != nil {
		t.Fatalf("CreateFirstPlatformAdmin: %v", err)
	}
	if got.ID == "" {
		t.Fatal("expected an admin id")
	}
	if got.Email != "ops@acme.com" {
		t.Fatalf("email = %q, want canonicalized ops@acme.com", got.Email)
	}
	if got.GeneratedPassword == "" {
		t.Fatal("blank password should yield a generated one")
	}
	if issues := passwords.ValidateStrength(got.GeneratedPassword); len(issues) != 0 {
		t.Fatalf("generated password is weak: %v", issues)
	}
	if n, _ := f.admins.CountPlatformAdmins(ctx); n != 1 {
		t.Fatalf("admin count = %d, want 1", n)
	}
	stored := f.admins.admins[0]
	if stored.PasswordHash == "" || stored.PasswordHash == got.GeneratedPassword {
		t.Fatal("must store a hash, never the raw password")
	}
	if stored.Status != PlatformAdminStatusActive {
		t.Fatalf("status = %q, want active", stored.Status)
	}
}

func TestCreateFirstPlatformAdmin_SuppliedPasswordNotReturned(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	ctx := context.Background()

	got, err := f.svc.CreateFirstPlatformAdmin(ctx, "ops@acme.com", "Str0ng!Bootstrap")
	if err != nil {
		t.Fatalf("CreateFirstPlatformAdmin: %v", err)
	}
	if got.GeneratedPassword != "" {
		t.Fatalf("supplied password must not be echoed back, got %q", got.GeneratedPassword)
	}
	if !passwords.Verify("Str0ng!Bootstrap", f.admins.admins[0].PasswordHash) {
		t.Fatal("stored hash must verify against the supplied password")
	}
}

func TestCreateFirstPlatformAdmin_WeakSuppliedPasswordRejected(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	if _, err := f.svc.CreateFirstPlatformAdmin(context.Background(), "ops@acme.com", "weak"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak password: err = %v, want ErrWeakPassword", err)
	}
	if n, _ := f.admins.CountPlatformAdmins(context.Background()); n != 0 {
		t.Fatal("a rejected bootstrap must not write anything")
	}
}

func TestCreateFirstPlatformAdmin_InvalidEmailRejected(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	if _, err := f.svc.CreateFirstPlatformAdmin(context.Background(), "not-an-email", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid email: err = %v, want ErrInvalidArgument", err)
	}
}

func TestCreateFirstPlatformAdmin_SecondCallRejected(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	ctx := context.Background()

	if _, err := f.svc.CreateFirstPlatformAdmin(ctx, "first@acme.com", ""); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	// Once an admin exists the path is permanently closed — even a different
	// email cannot create a second admin via the bootstrap.
	_, err := f.svc.CreateFirstPlatformAdmin(ctx, "second@acme.com", "")
	if !errors.Is(err, ErrPlatformAdminExists) {
		t.Fatalf("second bootstrap: err = %v, want ErrPlatformAdminExists", err)
	}
	if n, _ := f.admins.CountPlatformAdmins(ctx); n != 1 {
		t.Fatalf("admin count = %d, want exactly 1 after a rejected second bootstrap", n)
	}
}

func TestCreateFirstPlatformAdmin_ConcurrentCreatesExactlyOne(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	ctx := context.Background()

	const n = 16
	var wg sync.WaitGroup
	var successes int32
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := f.svc.CreateFirstPlatformAdmin(ctx, "ops@acme.com", "")
			if err == nil {
				atomic.AddInt32(&successes, 1)
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("concurrent bootstraps succeeded %d times, want exactly 1", successes)
	}
	for _, err := range errs {
		if err != nil && !errors.Is(err, ErrPlatformAdminExists) {
			t.Fatalf("loser error = %v, want nil or ErrPlatformAdminExists", err)
		}
	}
	if got, _ := f.admins.CountPlatformAdmins(ctx); got != 1 {
		t.Fatalf("admin count = %d, want exactly 1", got)
	}
}

func TestCreateFirstPlatformAdmin_UnimplementedWithoutStore(t *testing.T) {
	t.Parallel()
	// Built without a PlatformAdminStore (the entdb/memory shape).
	svc := NewControlPlaneAdminService("", newFakeControlPlaneStore(), newFakeTenantStore(), newFakeMembershipStore(), nil, nil)
	if _, err := svc.CreateFirstPlatformAdmin(context.Background(), "ops@acme.com", ""); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("no store: err = %v, want ErrUnimplemented", err)
	}
}
