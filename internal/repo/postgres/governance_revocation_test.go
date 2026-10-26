package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// The tenant and domain triggers of migration 0046 withdraw only the
// delegated agent authority a governance change governs, and only when the
// change moves governance. These tests write through the stores as the
// row-level-security app role, the role a deployment runs as.

const (
	govDomain      = "acme.example.test"
	govOtherDomain = "other.example.test"
)

// governanceFixture is one project with two claimed tenants and three people:
//   - member belongs to tenant, with an email on no tenant's domain;
//   - onDomain has an email on govDomain and no membership;
//   - outsider belongs to otherTenant, with an email on govOtherDomain.
type governanceFixture struct {
	project     string
	repo        *pgRepository
	raw         *pgx.Conn // superuser: seeds and reads agent rows past RLS
	tenants     *TenantStore
	domains     *DomainStore
	members     *MembershipStore
	client      string
	tenant      string
	otherTenant string
	member      string
	onDomain    string
	outsider    string
	seq         int
}

// authority is one person's delegated agent authority: a grant they gave, a
// grant they hold as an agent, and an agent machine they own.
type authority struct {
	given, held, machine string
}

func governanceDSNs(t *testing.T) (dsn, roleDSN string) {
	t.Helper()
	dsn = os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	require.NoError(t, Migrate(dsn))
	return dsn, provisionRLSAppRole(context.Background(), t, dsn)
}

func newGovernanceFixture(ctx context.Context, t *testing.T, dsn, roleDSN string) *governanceFixture {
	t.Helper()
	project := fmt.Sprintf("governance-%d", time.Now().UnixNano())
	admin, err := New(ctx, Config{DSN: dsn, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: project})
	require.NoError(t, err)
	t.Cleanup(admin.Close)
	seedProject(ctx, t, admin, project)

	repo, err := New(ctx, Config{DSN: roleDSN, MaxConns: 4, ConnTimeout: 5 * time.Second, ProjectID: project})
	require.NoError(t, err)
	t.Cleanup(repo.Close)
	raw, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close(context.WithoutCancel(ctx)) })

	client := &service.OAuthClient{
		ID: "governance-client", Kind: service.OAuthClientNativePublic, Revision: 1, CreatedAt: 1, UpdatedAt: 1,
		Registration: service.OAuthClientRegistration{
			Name: "Example desktop", RedirectURIs: []string{"http://127.0.0.1/callback"},
			Resources:  []service.OAuthResourceBounds{{Resource: "urn:example:files", Product: "files", Scopes: []string{"read"}}},
			GrantTypes: []string{service.OAuthGrantAuthorizationCode},
		},
	}
	require.NoError(t, repo.CreateOAuthClient(ctx, client))

	f := &governanceFixture{
		project: project, repo: repo, raw: raw, client: client.ID,
		tenants: NewTenantStore(repo), domains: NewDomainStore(repo), members: NewMembershipStore(repo),
	}
	newUser := func(email string) string {
		t.Helper()
		now := time.Now()
		id, err := repo.CreateUser(ctx, &service.User{Email: email, Status: "active", CreatedAt: now, UpdatedAt: now})
		require.NoError(t, err)
		return id
	}
	f.member = newUser("member@elsewhere.example.test")
	f.onDomain = newUser("person@" + govDomain)
	f.outsider = newUser("outsider@" + govOtherDomain)
	f.tenant = f.newTenant(ctx, t, "Acme", service.TenantStatusClaimed)
	f.otherTenant = f.newTenant(ctx, t, "Other", service.TenantStatusClaimed)
	f.join(ctx, t, f.tenant, f.member)
	f.join(ctx, t, f.otherTenant, f.outsider)
	return f
}

func (f *governanceFixture) newTenant(ctx context.Context, t *testing.T, name, status string) string {
	t.Helper()
	id, err := f.tenants.CreateTenant(ctx, &service.Tenant{ProjectID: f.project, Name: name, Status: status})
	require.NoError(t, err)
	return id
}

func (f *governanceFixture) join(ctx context.Context, t *testing.T, tenantID, userID string) {
	t.Helper()
	_, err := f.members.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: f.project, TenantID: tenantID, UserID: userID,
		Source: service.MembershipSourceAdded, Role: service.RoleMember, Status: service.MembershipStatusActive,
	})
	require.NoError(t, err)
}

func (f *governanceFixture) claim(ctx context.Context, t *testing.T, tenantID, domain, status string) string {
	t.Helper()
	id, err := f.domains.CreateDomain(ctx, &service.Domain{
		ProjectID: f.project, TenantID: tenantID, Domain: domain,
		VerificationMethod: service.DomainVerificationDNSTXT, Status: status,
	})
	require.NoError(t, err)
	return id
}

func (f *governanceFixture) nextID(prefix string) string {
	f.seq++
	return fmt.Sprintf("%s-%d", prefix, f.seq)
}

// grant inserts a live grant owned by owner and held by agent.
func (f *governanceFixture) grant(ctx context.Context, t *testing.T, owner, agent string) string {
	t.Helper()
	id := f.nextID("grant")
	_, err := f.raw.Exec(ctx, `INSERT INTO agent_authorizations(project_id,id,client_id,owner_id,agent_id,data_json,revision,expires_at_ms)
		VALUES($1,$2,$3,$4,$5,'{}',1,$6)`, f.project, id, f.client, owner, agent, time.Now().Add(time.Hour).UnixMilli())
	require.NoError(t, err)
	return id
}

// seedAuthority gives userID a live grant given, a live grant held, and a
// live machine.
func (f *governanceFixture) seedAuthority(ctx context.Context, t *testing.T, userID string) authority {
	t.Helper()
	a := authority{
		given:   f.grant(ctx, t, userID, f.nextID("agent")),
		held:    f.grant(ctx, t, f.nextID("owner"), userID),
		machine: f.nextID("machine"),
	}
	_, err := f.raw.Exec(ctx, `INSERT INTO agent_machines(project_id,id,owner_id,client_id,data_json,registration_json,revision)
		VALUES($1,$2,$3,$4,'{}','{}',1)`, f.project, a.machine, userID, f.client)
	require.NoError(t, err)
	return a
}

func (f *governanceFixture) revokedAt(ctx context.Context, t *testing.T, table, id string) int64 {
	t.Helper()
	var at int64
	require.NoError(t, f.raw.QueryRow(ctx,
		`SELECT revoked_at_ms FROM `+table+` WHERE project_id=$1 AND id=$2`, f.project, id).Scan(&at))
	return at
}

func (f *governanceFixture) requireIntact(ctx context.Context, t *testing.T, a authority, who string) {
	t.Helper()
	require.Zero(t, f.revokedAt(ctx, t, "agent_authorizations", a.given), "%s: the grant they gave", who)
	require.Zero(t, f.revokedAt(ctx, t, "agent_authorizations", a.held), "%s: the grant they hold", who)
	require.Zero(t, f.revokedAt(ctx, t, "agent_machines", a.machine), "%s: their machine", who)
}

func (f *governanceFixture) requireRevoked(ctx context.Context, t *testing.T, a authority, who string) {
	t.Helper()
	require.NotZero(t, f.revokedAt(ctx, t, "agent_authorizations", a.given), "%s: the grant they gave", who)
	require.NotZero(t, f.revokedAt(ctx, t, "agent_authorizations", a.held), "%s: the grant they hold", who)
	require.NotZero(t, f.revokedAt(ctx, t, "agent_machines", a.machine), "%s: their machine", who)
}

// everyone seeds fresh authority for the three people and an ownerless,
// still-pending authorization request.
type everyone struct {
	member, onDomain, outsider authority
	pending                    string
}

func (f *governanceFixture) seedEveryone(ctx context.Context, t *testing.T) everyone {
	t.Helper()
	return everyone{
		member:   f.seedAuthority(ctx, t, f.member),
		onDomain: f.seedAuthority(ctx, t, f.onDomain),
		outsider: f.seedAuthority(ctx, t, f.outsider),
		pending:  f.grant(ctx, t, "", ""),
	}
}

func (f *governanceFixture) requireNothingRevoked(ctx context.Context, t *testing.T, e everyone) {
	t.Helper()
	f.requireIntact(ctx, t, e.member, "member")
	f.requireIntact(ctx, t, e.onDomain, "on the domain")
	f.requireIntact(ctx, t, e.outsider, "outsider")
	require.Zero(t, f.revokedAt(ctx, t, "agent_authorizations", e.pending), "the ownerless pending request")
}

// requireGovernedRevoked asserts the change withdrew the authority of the
// tenant's member and of the account on its domain, and nobody else's.
func (f *governanceFixture) requireGovernedRevoked(ctx context.Context, t *testing.T, e everyone) {
	t.Helper()
	f.requireRevoked(ctx, t, e.member, "member")
	f.requireRevoked(ctx, t, e.onDomain, "on the domain")
	f.requireIntact(ctx, t, e.outsider, "outsider")
	require.Zero(t, f.revokedAt(ctx, t, "agent_authorizations", e.pending), "the ownerless pending request")
}

func TestGovernanceRevocation_UnprovenClaimsRevokeNothing(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newGovernanceFixture(ctx, t, dsn, roleDSN)
	e := f.seedEveryone(ctx, t)

	d := f.claim(ctx, t, f.tenant, govDomain, service.DomainStatusPending)
	require.NoError(t, f.domains.SetDomainStatus(ctx, f.project, d, service.DomainStatusFailed, 0))
	require.NoError(t, f.domains.SetDomainStatus(ctx, f.project, d, service.DomainStatusFailed, 0))
	require.NoError(t, f.domains.SetDomainStatus(ctx, f.project, d, service.DomainStatusPending, 0))
	_, err := f.repo.pool.Exec(ctx, `DELETE FROM domains WHERE project_id=$1 AND id=$2`, f.project, d)
	require.NoError(t, err)

	f.requireNothingRevoked(ctx, t, e)
}

func TestGovernanceRevocation_UnchangedWritesRevokeNothing(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newGovernanceFixture(ctx, t, dsn, roleDSN)
	d := f.claim(ctx, t, f.tenant, govDomain, service.DomainStatusVerified)
	e := f.seedEveryone(ctx, t)

	// A re-verify on a claimed tenant: the store skips both writes.
	require.NoError(t, f.domains.SetDomainStatus(ctx, f.project, d, service.DomainStatusVerified, 0))
	require.NoError(t, f.tenants.SetTenantStatus(ctx, f.project, f.tenant, service.TenantStatusClaimed))
	f.requireNothingRevoked(ctx, t, e)

	// Written outright, an unchanged row still fires nothing.
	_, err := f.repo.pool.Exec(ctx, `UPDATE domains SET status=status, tenant_id=tenant_id, domain=upper(domain) WHERE project_id=$1 AND id=$2`, f.project, d)
	require.NoError(t, err)
	_, err = f.repo.pool.Exec(ctx, `UPDATE tenants SET status=status, primary_domain=primary_domain WHERE project_id=$1 AND id=$2`, f.project, f.tenant)
	require.NoError(t, err)
	f.requireNothingRevoked(ctx, t, e)
}

func TestGovernanceRevocation_VerifiedTransitionsRevokeTheGoverned(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cases := map[string]func(t *testing.T, f *governanceFixture, d string){
		"pending to verified": func(t *testing.T, f *governanceFixture, d string) {
			t.Helper()
			require.NoError(t, f.domains.SetDomainStatus(ctx, f.project, d, service.DomainStatusVerified, 0))
		},
		// The store never moves a verified domain off verified, so this is
		// an operator's SQL: the trigger still governs it.
		"verified to failed": func(t *testing.T, f *governanceFixture, d string) {
			t.Helper()
			f.verifyQuietly(ctx, t, d)
			_, err := f.repo.pool.Exec(ctx, `UPDATE domains SET status=$3 WHERE project_id=$1 AND id=$2`,
				f.project, d, service.DomainStatusFailed)
			require.NoError(t, err)
		},
		"verified domain deleted": func(t *testing.T, f *governanceFixture, d string) {
			t.Helper()
			f.verifyQuietly(ctx, t, d)
			_, err := f.repo.pool.Exec(ctx, `DELETE FROM domains WHERE project_id=$1 AND id=$2`, f.project, d)
			require.NoError(t, err)
		},
		"verified domain renamed": func(t *testing.T, f *governanceFixture, d string) {
			t.Helper()
			f.verifyQuietly(ctx, t, d)
			_, err := f.repo.pool.Exec(ctx, `UPDATE domains SET domain='renamed.example.test' WHERE project_id=$1 AND id=$2`, f.project, d)
			require.NoError(t, err)
		},
		"tenant suspended": func(t *testing.T, f *governanceFixture, d string) {
			t.Helper()
			f.verifyQuietly(ctx, t, d)
			require.NoError(t, f.tenants.SetTenantStatus(ctx, f.project, f.tenant, service.TenantStatusSuspended))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newGovernanceFixture(ctx, t, dsn, roleDSN)
			d := f.claim(ctx, t, f.tenant, govDomain, service.DomainStatusPending)
			e := f.seedEveryone(ctx, t)
			change(t, f, d)
			f.requireGovernedRevoked(ctx, t, e)
		})
	}
}

// verifyQuietly marks d verified, then restores the project's agent rows the
// verification revoked, so the change under test is what the assertions see.
func (f *governanceFixture) verifyQuietly(ctx context.Context, t *testing.T, d string) {
	t.Helper()
	require.NoError(t, f.domains.SetDomainStatus(ctx, f.project, d, service.DomainStatusVerified, 0))
	_, err := f.raw.Exec(ctx, `UPDATE agent_authorizations SET revoked_at_ms=0 WHERE project_id=$1`, f.project)
	require.NoError(t, err)
	_, err = f.raw.Exec(ctx, `UPDATE agent_machines SET revoked_at_ms=0 WHERE project_id=$1`, f.project)
	require.NoError(t, err)
}

func TestGovernanceRevocation_InsertingAVerifiedDomainRevokesTheGoverned(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newGovernanceFixture(ctx, t, dsn, roleDSN)
	e := f.seedEveryone(ctx, t)

	f.claim(ctx, t, f.tenant, govDomain, service.DomainStatusVerified)
	f.requireGovernedRevoked(ctx, t, e)
}

func TestGovernanceRevocation_StaysInItsProject(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newGovernanceFixture(ctx, t, dsn, roleDSN)
	// Another project with a person on the same domain.
	g := newGovernanceFixture(ctx, t, dsn, roleDSN)
	theirs := g.seedEveryone(ctx, t)

	d := f.claim(ctx, t, f.tenant, govDomain, service.DomainStatusPending)
	require.NoError(t, f.domains.SetDomainStatus(ctx, f.project, d, service.DomainStatusVerified, 0))
	require.NoError(t, f.tenants.SetTenantStatus(ctx, f.project, f.tenant, service.TenantStatusSuspended))

	g.requireNothingRevoked(ctx, t, theirs)
}

// noTXT answers every TXT lookup with no records, so every DNS check fails.
type noTXT struct{}

func (noTXT) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }

// A self-service owner whose VerifyDomain fails, as often as they like,
// withdraws nobody's agent authority: not other tenants', not the project's.
func TestGovernanceRevocation_FailedSelfServiceVerifyRevokesNothing(t *testing.T) {
	dsn, roleDSN := governanceDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newGovernanceFixture(ctx, t, dsn, roleDSN)
	f.claim(ctx, t, f.otherTenant, govOtherDomain, service.DomainStatusVerified)

	now := time.Now()
	owner, err := f.repo.CreateUser(ctx, &service.User{Email: "owner@self.example.test", Status: "active", CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	owned, _, err := f.tenants.CreateOwnedTenant(ctx, service.OwnedTenantRequest{
		ProjectID: f.project, Name: "Self", OwnerID: owner, MaxPerWindow: 5,
	})
	require.NoError(t, err)
	e := f.seedEveryone(ctx, t)
	own := f.seedAuthority(ctx, t, owner)

	svc := service.NewDomainService(f.domains, f.tenants, f.members, noTXT{}, &config.Config{}, nil)
	pctx := service.WithProjectScope(ctx, &service.ProjectScope{
		ProjectID: f.project, Access: service.ProjectAccessConfig{Mode: service.AccessModeOpen},
	})
	created, err := svc.CreateDomain(pctx, owner, owned.ID, govDomain, service.DomainVerificationDNSTXT)
	require.NoError(t, err)
	for range 3 {
		_, err = svc.VerifyDomain(pctx, owner, created.Domain.ID)
		require.ErrorIs(t, err, service.ErrPermissionDenied)
	}
	d, err := f.domains.GetDomain(ctx, f.project, created.Domain.ID)
	require.NoError(t, err)
	require.Equal(t, service.DomainStatusFailed, d.Status)

	f.requireNothingRevoked(ctx, t, e)
	f.requireIntact(ctx, t, own, "the owner")
}

// TestGovernanceRevocationMigrationRoundTrip asserts 0046 down restores 0041's
// project-wide triggers and indexes, and up puts the scoped ones back.
func TestGovernanceRevocationMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	source, err := iofs.New(migrationFS, "migrations")
	require.NoError(t, err)
	defer func() { _ = source.Close() }()
	previous, err := source.Prev(46)
	require.NoError(t, err)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()

	triggerFunction := func(table, trigger string) string {
		t.Helper()
		var fn string
		err := raw.QueryRow(ctx, `SELECT p.proname FROM pg_trigger tr JOIN pg_proc p ON p.oid=tr.tgfoid
			WHERE tr.tgname=$1 AND tr.tgrelid=to_regclass($2)`, trigger, table).Scan(&fn)
		if errors.Is(err, pgx.ErrNoRows) {
			return ""
		}
		require.NoError(t, err)
		return fn
	}
	exists := func(relation string) bool {
		t.Helper()
		var ok bool
		require.NoError(t, raw.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, relation).Scan(&ok))
		return ok
	}
	for _, version := range []uint{46, previous, 46} {
		migrateToVersion(t, scratch, version)
		scoped := version == 46
		require.Equal(t, scoped, exists("domain_attempts"))
		require.Equal(t, scoped, exists("domains_project_email_domain_idx"))
		require.Equal(t, !scoped, exists("domains_project_tenant_idx"))
		require.Equal(t, !scoped, exists("tenant_invitations_project_tenant_idx"))
		require.Equal(t, scoped, exists("tenant_invitations_project_inviter_created_idx"))
		if scoped {
			require.Equal(t, "revoke_agent_oauth_tenant_governance", triggerFunction("tenants", "agent_oauth_tenant_policy"))
			require.Equal(t, "revoke_agent_oauth_domain_governance", triggerFunction("domains", "agent_oauth_domain_policy"))
			require.Equal(t, "revoke_agent_oauth_domain_governance", triggerFunction("domains", "agent_oauth_domain_delete"))
			require.Equal(t, "revoke_agent_oauth_domain_governance", triggerFunction("domains", "agent_oauth_verified_domain"))
		} else {
			require.Equal(t, "revoke_agent_oauth_governance_policy", triggerFunction("tenants", "agent_oauth_tenant_policy"))
			require.Equal(t, "revoke_agent_oauth_governance_policy", triggerFunction("domains", "agent_oauth_domain_policy"))
			require.Empty(t, triggerFunction("domains", "agent_oauth_domain_delete"))
			require.Equal(t, "revoke_agent_oauth_governance_policy", triggerFunction("domains", "agent_oauth_verified_domain"))
		}
	}
}
