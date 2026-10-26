package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestAgentOAuthRowLevelSecurityAndControlPlaneRevocation(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, Migrate(dsn))
	projectA := fmt.Sprintf("delegation-rls-a-%d", time.Now().UnixNano())
	projectB := projectA + "-other"
	admin, err := New(ctx, Config{DSN: dsn, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: projectA})
	require.NoError(t, err)
	defer admin.Close()
	seedProject(ctx, t, admin, projectA)
	seedProject(ctx, t, admin, projectB)
	roleDSN := provisionRLSAppRole(ctx, t, dsn)
	repo, err := New(ctx, Config{DSN: roleDSN, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: projectA})
	require.NoError(t, err)
	defer repo.Close()
	client := &service.OAuthClient{ID: "native-rls", Kind: service.OAuthClientNativePublic, Revision: 1, CreatedAt: 1, UpdatedAt: 1, Registration: service.OAuthClientRegistration{Name: "Example desktop", RedirectURIs: []string{"http://127.0.0.1/callback"}, Resources: []service.OAuthResourceBounds{{Resource: "urn:example:files", Product: "files", Scopes: []string{"read"}}}, GrantTypes: []string{service.OAuthGrantAuthorizationCode}}}
	require.NoError(t, repo.CreateOAuthClient(ctx, client))
	request := &service.AgentAuthorization{ID: "request-rls", ClientID: client.ID, ClientRevision: 1, RedirectURI: client.Registration.RedirectURIs[0], Resource: client.Registration.Resources[0].Resource, Product: "files", Scopes: []string{"read"}, Challenge: strings.Repeat("a", 43), Decision: service.AgentAuthorizationPending, Revision: 1, CreatedAtMs: 1, ExpiresAtMs: 60000}
	require.NoError(t, repo.CreateAgentAuthorization(ctx, request))
	raw, err := pgx.Connect(ctx, roleDSN)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	for _, project := range []string{"", projectB, projectA} {
		_, err = raw.Exec(ctx, `SELECT set_config('app.current_project_id',$1,false)`, project)
		require.NoError(t, err)
		var count int
		require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM agent_authorizations`).Scan(&count))
		if project == projectA {
			require.Equal(t, 1, count)
		} else {
			require.Zero(t, count)
			tag, err := raw.Exec(ctx, `UPDATE agent_authorizations SET revoked_at_ms=1`)
			require.NoError(t, err)
			require.Zero(t, tag.RowsAffected())
			_, err = raw.Exec(ctx, `INSERT INTO agent_oauth_refresh_tokens(project_id,token_hash,authorization_id,expires_at_ms) VALUES($1,'injected','request-rls',100)`, projectA)
			require.Error(t, err)
		}
	}
	_, err = raw.Exec(ctx, `SELECT set_config('app.current_project_id','',false)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `UPDATE projects SET status='suspended' WHERE id=$1`, projectA)
	require.NoError(t, err)
	var originalScope string
	require.NoError(t, raw.QueryRow(ctx, `SELECT current_setting('app.current_project_id',true)`).Scan(&originalScope))
	require.Empty(t, originalScope, "control-plane mutation must restore connection scope")
	stored, err := repo.GetAgentAuthorization(ctx, request.ID)
	require.NoError(t, err)
	require.NotZero(t, stored.RevokedAtMs, "project control-plane mutation must fence grants even without data-plane GUC")
	tenantID, err := NewTenantStore(repo).CreateTenant(ctx, &service.Tenant{ProjectID: projectA, Status: service.TenantStatusClaimed})
	require.NoError(t, err)
	// Tenant and domain changes revoke only the authority of the people they
	// govern (0046): give each grant they must revoke an owner on the domain.
	now := time.Now()
	governed, err := repo.CreateUser(ctx, &service.User{Email: "person@governance.example.test", Status: "active", CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	createOwned := func(id string) {
		t.Helper()
		grant := request.Clone()
		grant.ID = id
		require.NoError(t, repo.CreateAgentAuthorization(ctx, grant))
		_, err := raw.Exec(ctx, `SELECT set_config('app.current_project_id',$1,false)`, projectA)
		require.NoError(t, err)
		_, err = raw.Exec(ctx, `UPDATE agent_authorizations SET owner_id=$2 WHERE project_id=$1 AND id=$3`, projectA, governed, id)
		require.NoError(t, err)
		_, err = raw.Exec(ctx, `SELECT set_config('app.current_project_id','',false)`)
		require.NoError(t, err)
	}
	createOwned("new-verified-domain")
	domainID, err := NewDomainStore(repo).CreateDomain(ctx, &service.Domain{ProjectID: projectA, TenantID: tenantID, Domain: "governance.example.test", VerificationMethod: "dns_txt", Status: service.DomainStatusVerified})
	require.NoError(t, err)
	stored, err = repo.GetAgentAuthorization(ctx, "new-verified-domain")
	require.NoError(t, err)
	require.NotZero(t, stored.RevokedAtMs)
	other := repo.WithProject(projectB)
	require.NoError(t, other.CreateOAuthClient(ctx, client.Clone()))
	otherGrant := request.Clone()
	otherGrant.ID = "other-project-request"
	require.NoError(t, other.(service.AgentOAuthRepository).CreateAgentAuthorization(ctx, otherGrant))
	// Login-policy changes revoke project-wide, so even an ownerless pending
	// request goes; tenant and domain changes revoke the governed person's
	// grant and leave the ownerless one.
	operations := []struct {
		name, query string
		args        []any
		projectWide bool
	}{
		{"policy-insert", `INSERT INTO login_policies(id,project_id,tenant_id,created_at_ms,updated_at_ms) VALUES('delegation-policy',$1,$2,1,1)`, []any{projectA, tenantID}, true},
		{"policy-update", `UPDATE login_policies SET require_2fa=true WHERE project_id=$1 AND tenant_id=$2`, []any{projectA, tenantID}, true},
		{"policy-delete", `DELETE FROM login_policies WHERE project_id=$1 AND tenant_id=$2`, []any{projectA, tenantID}, true},
		{"tenant-status", `UPDATE tenants SET status='suspended' WHERE project_id=$1 AND id=$2`, []any{projectA, tenantID}, false},
		{"domain-status", `UPDATE domains SET status='failed' WHERE project_id=$1 AND id=$2`, []any{projectA, domainID}, false},
		{"domain-reverified", `UPDATE domains SET status='verified' WHERE project_id=$1 AND id=$2`, []any{projectA, domainID}, false},
		{"domain-delete", `DELETE FROM domains WHERE project_id=$1 AND id=$2`, []any{projectA, domainID}, false},
	}
	for _, operation := range operations {
		ownerless := request.Clone()
		ownerless.ID = operation.name + "-ownerless"
		require.NoError(t, repo.CreateAgentAuthorization(ctx, ownerless))
		createOwned(operation.name)
		_, err = raw.Exec(ctx, operation.query, operation.args...)
		require.NoError(t, err)
		stored, err = repo.GetAgentAuthorization(ctx, operation.name)
		require.NoError(t, err)
		require.NotZero(t, stored.RevokedAtMs, operation.name)
		stored, err = repo.GetAgentAuthorization(ctx, ownerless.ID)
		require.NoError(t, err)
		require.Equal(t, operation.projectWide, stored.RevokedAtMs != 0, operation.name+": the ownerless request")
		require.NoError(t, raw.QueryRow(ctx, `SELECT current_setting('app.current_project_id',true)`).Scan(&originalScope))
		require.Empty(t, originalScope)
	}
	untouched, err := other.(service.AgentOAuthRepository).GetAgentAuthorization(ctx, otherGrant.ID)
	require.NoError(t, err)
	require.Zero(t, untouched.RevokedAtMs, "governance changes must not cross projects")
}

func TestAgentOAuthMigrationRoundTrip(t *testing.T) {
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
	previous, err := source.Prev(41)
	require.NoError(t, err)
	migrateToVersion(t, scratch, previous)
	raw, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	for _, version := range []uint{41, previous, 41} {
		migrateToVersion(t, scratch, version)
		for _, table := range []string{"agent_authorizations", "agent_oauth_refresh_tokens"} {
			var exists bool
			require.NoError(t, raw.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists))
			require.Equal(t, version == 41, exists)
		}
		var registry bool
		require.NoError(t, raw.QueryRow(ctx, `SELECT to_regclass('oauth_clients') IS NOT NULL`).Scan(&registry))
		require.True(t, registry, "delegation rollback must retain native registrations")
	}
}
