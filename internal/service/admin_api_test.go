package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// fakeControlPlaneStore is an in-memory ControlPlaneProjectStore. It reuses
// the same nil-on-miss conventions as the real postgres store and records
// what it was handed so the credential-hashing and auth-domain seeding can be
// asserted without a database.
type fakeControlPlaneStore struct {
	projects    map[string]*AdminProject
	credentials map[string]*AdminProjectCredential
	authDomains map[string]string                             // hostname → projectID (ownership, any state)
	domainRows  map[string]map[string]*AdminProjectAuthDomain // projectID → hostname → row
	configs     map[string]string                             // projectID → config_json
	// configVersions is the per-project optimistic-concurrency token the real
	// postgres store keeps in the config_version column; the fake tracks it so it
	// enforces the same compare-and-swap semantics the service retry loop relies
	// on. configMu guards configs/configVersions so the concurrent-RMW tests run
	// clean under -race.
	configVersions map[string]int64
	configMu       sync.Mutex
	// forceConflict makes every UpdateProjectConfig lose its CAS, so a test can
	// drive the retry loop to exhaustion (ErrProjectConfigConflict → Aborted).
	forceConflict bool
	// updateErr makes UpdateProjectConfig fail with a NON-conflict store error, so
	// a test can prove the retry helper surfaces such an error immediately rather
	// than retrying it.
	updateErr  error
	createErr  error
	credErr    error
	domainErr  error
	nextID     int
	lastDomain struct {
		projectID    string
		hostname     string
		isPrimary    bool
		verifiedAtMs int64
	}
}

func newFakeControlPlaneStore() *fakeControlPlaneStore {
	return &fakeControlPlaneStore{
		projects:       map[string]*AdminProject{},
		credentials:    map[string]*AdminProjectCredential{},
		authDomains:    map[string]string{},
		domainRows:     map[string]map[string]*AdminProjectAuthDomain{},
		configs:        map[string]string{},
		configVersions: map[string]int64{},
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
	f.putDomain(projectID, hostname, isPrimary, verifiedAtMs)
	f.lastDomain.projectID = projectID
	f.lastDomain.hostname = hostname
	f.lastDomain.isPrimary = isPrimary
	f.lastDomain.verifiedAtMs = verifiedAtMs
	return nil
}

func (f *fakeControlPlaneStore) putDomain(projectID, hostname string, isPrimary bool, verifiedAtMs int64) {
	f.authDomains[hostname] = projectID
	if f.domainRows[projectID] == nil {
		f.domainRows[projectID] = map[string]*AdminProjectAuthDomain{}
	}
	f.domainRows[projectID][hostname] = &AdminProjectAuthDomain{
		Hostname:     hostname,
		IsPrimary:    isPrimary,
		VerifiedAtMs: verifiedAtMs,
	}
}

func (f *fakeControlPlaneStore) CreateAuthDomain(_ context.Context, projectID, hostname string, isPrimary bool) error {
	if f.domainErr != nil {
		return f.domainErr
	}
	if owner, ok := f.authDomains[hostname]; ok && owner != projectID {
		return ErrAlreadyExists
	}
	if _, ok := f.domainRows[projectID][hostname]; ok {
		return ErrAlreadyExists
	}
	f.putDomain(projectID, hostname, isPrimary, 0) // unverified
	return nil
}

func (f *fakeControlPlaneStore) GetAuthDomain(_ context.Context, projectID, hostname string) (*AdminProjectAuthDomain, error) {
	if f.domainErr != nil {
		return nil, f.domainErr
	}
	d := f.domainRows[projectID][hostname]
	if d == nil {
		return nil, nil
	}
	cp := *d
	return &cp, nil
}

func (f *fakeControlPlaneStore) ListAuthDomains(_ context.Context, projectID string) ([]*AdminProjectAuthDomain, error) {
	if f.domainErr != nil {
		return nil, f.domainErr
	}
	var out []*AdminProjectAuthDomain
	for _, d := range f.domainRows[projectID] {
		cp := *d
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeControlPlaneStore) SetAuthDomainVerified(_ context.Context, projectID, hostname string, verifiedAtMs int64) error {
	if f.domainErr != nil {
		return f.domainErr
	}
	d := f.domainRows[projectID][hostname]
	if d == nil {
		return ErrNotFound
	}
	d.VerifiedAtMs = verifiedAtMs
	return nil
}

func (f *fakeControlPlaneStore) SetPrimaryAuthDomain(_ context.Context, projectID, hostname string) (*AdminProjectAuthDomain, error) {
	if f.domainErr != nil {
		return nil, f.domainErr
	}
	target := f.domainRows[projectID][hostname]
	if target == nil {
		return nil, ErrNotFound
	}
	if target.VerifiedAtMs <= 0 {
		return nil, ErrAuthDomainNotVerified
	}
	for _, d := range f.domainRows[projectID] {
		d.IsPrimary = false
	}
	target.IsPrimary = true
	cp := *target
	return &cp, nil
}

func (f *fakeControlPlaneStore) UpdateProjectConfig(_ context.Context, projectID string, expectedVersion int64, configJSON string) (string, int64, error) {
	f.configMu.Lock()
	defer f.configMu.Unlock()
	if _, ok := f.projects[projectID]; !ok {
		return "", 0, ErrNotFound
	}
	if f.updateErr != nil {
		return "", 0, f.updateErr
	}
	if f.forceConflict || f.configVersions[projectID] != expectedVersion {
		return "", 0, ErrProjectConfigConflict
	}
	if strings.TrimSpace(configJSON) == "" {
		configJSON = "{}"
	}
	f.configs[projectID] = configJSON
	f.configVersions[projectID] = expectedVersion + 1
	return configJSON, expectedVersion + 1, nil
}

func (f *fakeControlPlaneStore) GetProjectConfig(_ context.Context, projectID string) (string, int64, error) {
	f.configMu.Lock()
	defer f.configMu.Unlock()
	if _, ok := f.projects[projectID]; !ok {
		return "", 0, ErrNotFound
	}
	cfg, ok := f.configs[projectID]
	if !ok {
		cfg = "{}"
	}
	return cfg, f.configVersions[projectID], nil
}

var _ ControlPlaneProjectStore = (*fakeControlPlaneStore)(nil)

// fakeLoginPolicyStore is an in-memory LoginPolicyStore for the admin-policy
// service tests: one policy per (projectID, tenantID), nil-on-miss.
type fakeLoginPolicyStore struct {
	policies map[string]*LoginPolicy // projectID|tenantID → policy
	nextID   int
	upErr    error
	getErr   error
	delErr   error
}

func newFakeLoginPolicyStore() *fakeLoginPolicyStore {
	return &fakeLoginPolicyStore{policies: map[string]*LoginPolicy{}}
}

func lpKey(projectID, tenantID string) string { return projectID + "|" + tenantID }

func (f *fakeLoginPolicyStore) UpsertLoginPolicy(_ context.Context, p *LoginPolicy) (string, error) {
	if f.upErr != nil {
		return "", f.upErr
	}
	if p == nil || p.ProjectID == "" || p.TenantID == "" {
		return "", ErrInvalidArgument
	}
	k := lpKey(p.ProjectID, p.TenantID)
	now := int64(1)
	if existing, ok := f.policies[k]; ok {
		p.ID = existing.ID
		p.CreatedAtMs = existing.CreatedAtMs
	} else {
		f.nextID++
		p.ID = "lp-" + itoa(f.nextID)
		p.CreatedAtMs = now
	}
	p.UpdatedAtMs = now
	if p.SSOConnectionJSON == "" {
		p.SSOConnectionJSON = "{}"
	}
	cp := *p
	f.policies[k] = &cp
	return p.ID, nil
}

func (f *fakeLoginPolicyStore) GetLoginPolicy(_ context.Context, projectID, tenantID string) (*LoginPolicy, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if projectID == "" || tenantID == "" {
		return nil, nil
	}
	if p, ok := f.policies[lpKey(projectID, tenantID)]; ok {
		cp := *p
		return &cp, nil
	}
	return nil, nil
}

func (f *fakeLoginPolicyStore) DeleteLoginPolicy(_ context.Context, projectID, tenantID string) error {
	if f.delErr != nil {
		return f.delErr
	}
	if projectID == "" || tenantID == "" {
		return ErrInvalidArgument
	}
	delete(f.policies, lpKey(projectID, tenantID))
	return nil
}

var _ LoginPolicyStore = (*fakeLoginPolicyStore)(nil)

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
	mu          sync.Mutex
	admins      []*PlatformAdmin
	createErr   error
	nextID      int
	createCalls int // how many times the locked CreateFirstPlatformAdmin ran
}

func newFakePlatformAdminStore() *fakePlatformAdminStore {
	return &fakePlatformAdminStore{}
}

func (f *fakePlatformAdminStore) CreateFirstPlatformAdmin(_ context.Context, a *PlatformAdmin) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
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
	policies *fakeLoginPolicyStore
	admins   *fakePlatformAdminStore
	dns      *fakeDNSResolver
	audit    *recordingAuditWriter
}

// testAdminSecretsKey is a fixed 32-byte AES-256 key the admin fixture uses to
// encrypt per-project OAuth secrets, so an encrypted secret round-trips through
// the resolver's decrypt path in tests.
func testAdminSecretsKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func newAdminFixture(secret string) *adminFixture {
	return newAdminFixtureWithKey(secret, testAdminSecretsKey())
}

func newAdminFixtureWithKey(secret string, secretsKey []byte) *adminFixture {
	return newAdminFixtureFull(secret, false, secretsKey)
}

func newAdminFixtureFull(secret string, disableBootstrap bool, secretsKey []byte) *adminFixture {
	p := newFakeControlPlaneStore()
	t := newFakeTenantStore()
	m := newFakeMembershipStore()
	lp := newFakeLoginPolicyStore()
	a := newFakePlatformAdminStore()
	dns := &fakeDNSResolver{records: map[string][]string{}}
	auditWriter := newRecordingAuditWriter()
	auditLog := audit.NewLogger(auditWriter, "test-project", zap.NewNop())
	return &adminFixture{
		svc:      NewControlPlaneAdminService(secret, disableBootstrap, secretsKey, p, t, m, lp, a, dns, auditLog, zap.NewNop()),
		projects: p,
		tenants:  t,
		members:  m,
		policies: lp,
		admins:   a,
		dns:      dns,
		audit:    auditWriter,
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

// ── customer custom auth-domains: add → verify → list ────────────────────

func TestControlPlaneAdmin_AddCustomAuthDomain_Unverified(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	reg, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "  Auth.Customer.COM ", false)
	if err != nil {
		t.Fatalf("AddProjectAuthDomain: %v", err)
	}
	if reg.Domain.Hostname != "auth.customer.com" {
		t.Fatalf("hostname not normalized: %q", reg.Domain.Hostname)
	}
	if reg.Domain.VerifiedAtMs != 0 {
		t.Fatalf("a customer domain must start unverified, got verified_at_ms=%d", reg.Domain.VerifiedAtMs)
	}
	// The TXT challenge is deterministic and prefixed.
	if reg.TXTName != "auth.customer.com" {
		t.Fatalf("txt name = %q, want the hostname", reg.TXTName)
	}
	if !strings.HasPrefix(reg.TXTValue, authDomainVerifyTXTPrefix) {
		t.Fatalf("txt value %q lacks prefix %q", reg.TXTValue, authDomainVerifyTXTPrefix)
	}
	// Re-adding returns the SAME deterministic challenge, no conflict.
	reg2, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "auth.customer.com", false)
	if err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if reg2.TXTValue != reg.TXTValue {
		t.Fatalf("re-issued challenge %q differs from %q", reg2.TXTValue, reg.TXTValue)
	}
}

func TestControlPlaneAdmin_AddCustomAuthDomain_Primary_Rejected(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	// Promoting a custom auth-domain to primary is a planned follow-up: a
	// request with is_primary=true is rejected, and registers nothing.
	if _, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "auth.customer.com", true); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("AddProjectAuthDomain(is_primary=true): err = %v, want ErrInvalidArgument", err)
	}
	d, err := f.projects.GetAuthDomain(ctx, "proj-1", "auth.customer.com")
	if err != nil {
		t.Fatalf("GetAuthDomain: %v", err)
	}
	if d != nil {
		t.Fatalf("a rejected primary add must register nothing, got %+v", d)
	}

	// The default (is_primary=false) still works end to end: add registers the
	// domain NON-primary and unverified, verification flips verified_at_ms.
	reg, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "auth.customer.com", false)
	if err != nil {
		t.Fatalf("AddProjectAuthDomain(is_primary=false): %v", err)
	}
	if reg.Domain.IsPrimary {
		t.Fatal("a custom auth-domain must be added non-primary")
	}
	if reg.Domain.VerifiedAtMs != 0 {
		t.Fatalf("must start unverified, got verified_at_ms=%d", reg.Domain.VerifiedAtMs)
	}
	f.dns.records["auth.customer.com"] = []string{reg.TXTValue}
	verified, err := f.svc.VerifyProjectAuthDomain(ctx, testAdminSecret, "proj-1", "auth.customer.com")
	if err != nil {
		t.Fatalf("VerifyProjectAuthDomain: %v", err)
	}
	if verified.VerifiedAtMs <= 0 {
		t.Fatalf("verify must stamp verified_at_ms positive, got %d", verified.VerifiedAtMs)
	}
}

func TestControlPlaneAdmin_VerifyCustomAuthDomain_WrongOrMissingTXT_StaysUnverified(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	_, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "auth.customer.com", false)
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	// No TXT record at all → verification failure, domain stays unverified.
	if _, err := f.svc.VerifyProjectAuthDomain(ctx, testAdminSecret, "proj-1", "auth.customer.com"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("missing TXT: err = %v, want ErrPermissionDenied", err)
	}
	d, _ := f.projects.GetAuthDomain(ctx, "proj-1", "auth.customer.com")
	if d.VerifiedAtMs != 0 {
		t.Fatalf("domain must stay unverified after a failed verify, got %d", d.VerifiedAtMs)
	}

	// A wrong TXT value → still fails.
	f.dns.records["auth.customer.com"] = []string{"some-other-value", authDomainVerifyTXTPrefix + "deadbeef"}
	if _, err := f.svc.VerifyProjectAuthDomain(ctx, testAdminSecret, "proj-1", "auth.customer.com"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("wrong TXT: err = %v, want ErrPermissionDenied", err)
	}
	d, _ = f.projects.GetAuthDomain(ctx, "proj-1", "auth.customer.com")
	if d.VerifiedAtMs != 0 {
		t.Fatal("domain must stay unverified after a wrong-TXT verify")
	}
}

func TestControlPlaneAdmin_VerifyCustomAuthDomain_CorrectTXT_FlipsVerified(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	reg, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "auth.customer.com", false)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	// Publish the exact challenge.
	f.dns.records["auth.customer.com"] = []string{"unrelated", reg.TXTValue}

	d, err := f.svc.VerifyProjectAuthDomain(ctx, testAdminSecret, "proj-1", "auth.customer.com")
	if err != nil {
		t.Fatalf("verify with correct TXT: %v", err)
	}
	if d.VerifiedAtMs <= 0 {
		t.Fatalf("verified_at_ms must be stamped positive, got %d", d.VerifiedAtMs)
	}

	// Re-verify is idempotent and does not move the timestamp.
	first := d.VerifiedAtMs
	d2, err := f.svc.VerifyProjectAuthDomain(ctx, testAdminSecret, "proj-1", "auth.customer.com")
	if err != nil {
		t.Fatalf("re-verify: %v", err)
	}
	if d2.VerifiedAtMs != first {
		t.Fatalf("re-verify moved the timestamp: %d → %d", first, d2.VerifiedAtMs)
	}
}

func TestControlPlaneAdmin_VerifyCustomAuthDomain_UnknownHost_NotFound(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	if _, err := f.svc.VerifyProjectAuthDomain(context.Background(), testAdminSecret, "proj-1", "never.added.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("verify unknown host: err = %v, want ErrNotFound", err)
	}
}

func TestControlPlaneAdmin_ListCustomAuthDomains(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	if _, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "a.customer.com", false); err != nil {
		t.Fatalf("add a: %v", err)
	}
	if _, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "b.customer.com", false); err != nil {
		t.Fatalf("add b: %v", err)
	}
	got, err := f.svc.ListProjectAuthDomains(ctx, testAdminSecret, "proj-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("listed %d domains, want 2", len(got))
	}
}

func TestControlPlaneAdmin_SetPrimaryAuthDomain_PromotesVerifiedAndDemotesOld(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	// Seed an existing verified primary, then add+verify a second custom domain.
	f.projects.putDomain("proj-1", "old.customer.com", true, 1)
	reg, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "new.customer.com", false)
	if err != nil {
		t.Fatalf("add new: %v", err)
	}
	f.dns.records["new.customer.com"] = []string{reg.TXTValue}
	if _, err := f.svc.VerifyProjectAuthDomain(ctx, testAdminSecret, "proj-1", "new.customer.com"); err != nil {
		t.Fatalf("verify new: %v", err)
	}

	promoted, err := f.svc.SetPrimaryAuthDomain(ctx, testAdminSecret, "proj-1", "new.customer.com")
	if err != nil {
		t.Fatalf("SetPrimaryAuthDomain: %v", err)
	}
	if !promoted.IsPrimary || promoted.Hostname != "new.customer.com" {
		t.Fatalf("promoted = %+v, want new.customer.com primary", promoted)
	}
	old, _ := f.projects.GetAuthDomain(ctx, "proj-1", "old.customer.com")
	if old.IsPrimary {
		t.Fatal("the old primary must be demoted")
	}
}

func TestControlPlaneAdmin_SetPrimaryAuthDomain_UnverifiedRejected(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	if _, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "proj-1", "pending.customer.com", false); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := f.svc.SetPrimaryAuthDomain(ctx, testAdminSecret, "proj-1", "pending.customer.com"); !errors.Is(err, ErrAuthDomainNotVerified) {
		t.Fatalf("promote unverified: err = %v, want ErrAuthDomainNotVerified", err)
	}
}

func TestControlPlaneAdmin_SetPrimaryAuthDomain_UnknownHost_NotFound(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	if _, err := f.svc.SetPrimaryAuthDomain(context.Background(), testAdminSecret, "proj-1", "never.added.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("promote unknown: err = %v, want ErrNotFound", err)
	}
}

func TestControlPlaneAdmin_SetPrimaryAuthDomain_ValidateArgsAndSecret(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()
	if _, err := f.svc.SetPrimaryAuthDomain(ctx, "wrong", "proj-1", "h.example.com"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("wrong secret: err = %v, want ErrPermissionDenied", err)
	}
	if _, err := f.svc.SetPrimaryAuthDomain(ctx, testAdminSecret, " ", "h.example.com"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank project id: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := f.svc.SetPrimaryAuthDomain(ctx, testAdminSecret, "proj-1", "no-dot"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid hostname: err = %v, want ErrInvalidArgument", err)
	}
}

func TestControlPlaneAdmin_CustomDomainRPCs_ValidateArgs(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	if _, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "  ", "h.example.com", false); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank project id: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := f.svc.AddProjectAuthDomain(ctx, testAdminSecret, "p", "no-dot", false); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid hostname: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := f.svc.VerifyProjectAuthDomain(ctx, testAdminSecret, "p", "  "); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank hostname: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := f.svc.ListProjectAuthDomains(ctx, testAdminSecret, " "); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("blank project id (list): err = %v, want ErrInvalidArgument", err)
	}
}

func TestControlPlaneAdmin_CustomDomainRPCs_Gated(t *testing.T) {
	t.Parallel()
	// Disabled surface → Unimplemented.
	dis := newAdminFixture("")
	ctx := context.Background()
	if _, err := dis.svc.AddProjectAuthDomain(ctx, "x", "p", "h.example.com", false); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("AddProjectAuthDomain disabled: err = %v, want ErrUnimplemented", err)
	}
	if _, err := dis.svc.VerifyProjectAuthDomain(ctx, "x", "p", "h.example.com"); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("VerifyProjectAuthDomain disabled: err = %v, want ErrUnimplemented", err)
	}
	if _, err := dis.svc.ListProjectAuthDomains(ctx, "x", "p"); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("ListProjectAuthDomains disabled: err = %v, want ErrUnimplemented", err)
	}

	// Wrong secret → PermissionDenied.
	en := newAdminFixture(testAdminSecret)
	if _, err := en.svc.AddProjectAuthDomain(ctx, "wrong", "p", "h.example.com", false); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("AddProjectAuthDomain wrong secret: err = %v, want ErrPermissionDenied", err)
	}
	if _, err := en.svc.VerifyProjectAuthDomain(ctx, "wrong", "p", "h.example.com"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("VerifyProjectAuthDomain wrong secret: err = %v, want ErrPermissionDenied", err)
	}
	if _, err := en.svc.ListProjectAuthDomains(ctx, "wrong", "p"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("ListProjectAuthDomains wrong secret: err = %v, want ErrPermissionDenied", err)
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
		if _, err := f.svc.CreateFirstPlatformAdmin(ctx, testAdminSecret, "ops@acme.com", "Str0ng!Bootstrap"); !errors.Is(err, wantErr) {
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

	got, err := f.svc.CreateFirstPlatformAdmin(ctx, "", "  Ops@Acme.com ", "")
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

	got, err := f.svc.CreateFirstPlatformAdmin(ctx, "", "ops@acme.com", "Str0ng!Bootstrap")
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
	if _, err := f.svc.CreateFirstPlatformAdmin(context.Background(), "", "ops@acme.com", "weak"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak password: err = %v, want ErrWeakPassword", err)
	}
	if n, _ := f.admins.CountPlatformAdmins(context.Background()); n != 0 {
		t.Fatal("a rejected bootstrap must not write anything")
	}
}

func TestCreateFirstPlatformAdmin_InvalidEmailRejected(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	if _, err := f.svc.CreateFirstPlatformAdmin(context.Background(), "", "not-an-email", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid email: err = %v, want ErrInvalidArgument", err)
	}
}

func TestCreateFirstPlatformAdmin_SecondCallRejected(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	ctx := context.Background()

	if _, err := f.svc.CreateFirstPlatformAdmin(ctx, "", "first@acme.com", ""); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	// Once an admin exists the path is permanently closed — even a different
	// email cannot create a second admin via the bootstrap.
	_, err := f.svc.CreateFirstPlatformAdmin(ctx, "", "second@acme.com", "")
	if !errors.Is(err, ErrPlatformAdminExists) {
		t.Fatalf("second bootstrap: err = %v, want ErrPlatformAdminExists", err)
	}
	if n, _ := f.admins.CountPlatformAdmins(ctx); n != 1 {
		t.Fatalf("admin count = %d, want exactly 1 after a rejected second bootstrap", n)
	}
}

func TestCreateFirstPlatformAdmin_BlockedAttemptEmitsAudit(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	ctx := context.Background()

	if _, err := f.svc.CreateFirstPlatformAdmin(ctx, "", "first@acme.com", ""); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	// The happy bootstrap must NOT emit a blocked event.
	if n := f.audit.countByEventType(string(audit.EventPlatformAdminBootstrapBlocked)); n != 0 {
		t.Fatalf("blocked events after happy bootstrap = %d, want 0", n)
	}

	// A second (now-closed) attempt must be rejected AND recorded so a
	// closed-bootstrap probe is visible in the audit trail.
	if _, err := f.svc.CreateFirstPlatformAdmin(ctx, "", "probe@evil.com", ""); !errors.Is(err, ErrPlatformAdminExists) {
		t.Fatalf("second bootstrap: err = %v, want ErrPlatformAdminExists", err)
	}
	if n := f.audit.countByEventType(string(audit.EventPlatformAdminBootstrapBlocked)); n != 1 {
		t.Fatalf("blocked events after closed-bootstrap probe = %d, want 1", n)
	}
	// The closed-bootstrap probe is recorded with the already_provisioned reason,
	// distinguishing it from a secret-denied or disabled denial.
	if n := f.audit.countByEventTypeAndDetail(string(audit.EventPlatformAdminBootstrapBlocked), "reason", bootstrapBlockedAlreadyProvisioned); n != 1 {
		t.Fatalf("already_provisioned blocked events = %d, want 1", n)
	}
	// Perf contract: the unlocked CountPlatformAdmins pre-check must have
	// short-circuited the closed-bootstrap probe BEFORE the advisory-lock
	// transaction — so the locked create ran exactly once (the real bootstrap).
	f.admins.mu.Lock()
	calls := f.admins.createCalls
	f.admins.mu.Unlock()
	if calls != 1 {
		t.Fatalf("locked CreateFirstPlatformAdmin calls = %d, want 1 (pre-check should skip the closed probe)", calls)
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
			_, err := f.svc.CreateFirstPlatformAdmin(ctx, "", "ops@acme.com", "")
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
	// Built without a PlatformAdminStore (the memory shape).
	svc := NewControlPlaneAdminService("", false, nil, newFakeControlPlaneStore(), newFakeTenantStore(), newFakeMembershipStore(), nil, nil, nil, nil, nil)
	if _, err := svc.CreateFirstPlatformAdmin(context.Background(), "", "ops@acme.com", ""); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("no store: err = %v, want ErrUnimplemented", err)
	}
}

// ── bootstrap hardening: secret-gated when a secret is configured ─────────

func TestCreateFirstPlatformAdmin_SecretConfigured_WrongOrMissingSecretDenied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A wrong, blank, or near-miss presented secret is rejected uniformly, and
	// nothing is written — a fresh internet-exposed deploy cannot have an
	// anonymous caller win the first-admin race once a secret is configured.
	for _, presented := range []string{"", "wrong", testAdminSecret + "x", testAdminSecret[:len(testAdminSecret)-1]} {
		f := newAdminFixture(testAdminSecret)
		if _, err := f.svc.CreateFirstPlatformAdmin(ctx, presented, "ops@acme.com", ""); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("CreateFirstPlatformAdmin(secret=%q): err = %v, want ErrPermissionDenied", presented, err)
		}
		if n, _ := f.admins.CountPlatformAdmins(ctx); n != 0 {
			t.Fatalf("secret=%q: admin count = %d, want 0 (a denied bootstrap must not write)", presented, n)
		}
		// The denial must be auditable — a secret-denied probe against a hardened
		// deployment is exactly the signal this feature exists to surface.
		if n := f.audit.countByEventTypeAndDetail(string(audit.EventPlatformAdminBootstrapBlocked), "reason", bootstrapBlockedSecretDenied); n != 1 {
			t.Fatalf("secret=%q: secret_denied blocked events = %d, want 1", presented, n)
		}
	}
}

func TestCreateFirstPlatformAdmin_SecretConfigured_CorrectSecretSucceeds(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(testAdminSecret)
	ctx := context.Background()

	got, err := f.svc.CreateFirstPlatformAdmin(ctx, testAdminSecret, "ops@acme.com", "")
	if err != nil {
		t.Fatalf("CreateFirstPlatformAdmin with correct secret: %v", err)
	}
	if got.ID == "" || got.Email != "ops@acme.com" || got.GeneratedPassword == "" {
		t.Fatalf("response = %+v", got)
	}
	if n, _ := f.admins.CountPlatformAdmins(ctx); n != 1 {
		t.Fatalf("admin count = %d, want 1", n)
	}
	// A successful bootstrap must NOT emit any blocked-bootstrap event.
	if n := f.audit.countByEventType(string(audit.EventPlatformAdminBootstrapBlocked)); n != 0 {
		t.Fatalf("blocked events after a successful secret-gated bootstrap = %d, want 0", n)
	}
}

func TestCreateFirstPlatformAdmin_NoSecretConfigured_IgnoresPresentedSecret(t *testing.T) {
	t.Parallel()
	// TOFU stays zero-config ONLY when no secret is set: a presented secret is
	// simply ignored, so a fresh deployer's headless bootstrap keeps working.
	f := newAdminFixture("")
	ctx := context.Background()

	if _, err := f.svc.CreateFirstPlatformAdmin(ctx, "some-unexpected-value", "ops@acme.com", ""); err != nil {
		t.Fatalf("zero-config bootstrap must ignore a presented secret: %v", err)
	}
	if n, _ := f.admins.CountPlatformAdmins(ctx); n != 1 {
		t.Fatalf("admin count = %d, want 1", n)
	}
	// The zero-config success path must NOT emit any blocked-bootstrap event.
	if n := f.audit.countByEventType(string(audit.EventPlatformAdminBootstrapBlocked)); n != 0 {
		t.Fatalf("blocked events after a zero-config bootstrap = %d, want 0", n)
	}
}

func TestCreateFirstPlatformAdmin_Disabled_RejectedEvenWithCorrectSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// GATEWAY_DISABLE_FIRST_ADMIN_BOOTSTRAP closes the surface entirely: the RPC
	// is rejected regardless of admin existence and regardless of a correct
	// secret, for operators who bootstrap the first admin out-of-band.
	cases := []struct {
		name      string
		secret    string
		presented string
	}{
		{"no secret configured", "", ""},
		{"secret configured, correct secret presented", testAdminSecret, testAdminSecret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdminFixtureFull(tc.secret, true, testAdminSecretsKey())
			if _, err := f.svc.CreateFirstPlatformAdmin(ctx, tc.presented, "ops@acme.com", ""); !errors.Is(err, ErrFirstAdminBootstrapDisabled) {
				t.Fatalf("err = %v, want ErrFirstAdminBootstrapDisabled", err)
			}
			if n, _ := f.admins.CountPlatformAdmins(ctx); n != 0 {
				t.Fatalf("admin count = %d, want 0 (a disabled bootstrap must not write)", n)
			}
			// A closed-bootstrap probe must be auditable with a distinct reason.
			if n := f.audit.countByEventTypeAndDetail(string(audit.EventPlatformAdminBootstrapBlocked), "reason", bootstrapBlockedDisabled); n != 1 {
				t.Fatalf("bootstrap_disabled blocked events = %d, want 1", n)
			}
		})
	}
}
