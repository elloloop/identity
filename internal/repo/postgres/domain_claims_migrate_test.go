package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// domainClaimsMigrationVersion is 0045, which lets tenants contest a domain.
const domainClaimsMigrationVersion = 45

// TestMigrate_0045ContestsDomainClaims: on upgrade every dns_txt registration
// that already exists keeps the project-wide challenge it was issued, and an
// email one does not; afterwards a second tenant may claim a domain. A
// downgrade restores one row per domain, keeping the verified claim, else
// the oldest.
func TestMigrate_0045ContestsDomainClaims(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping real-postgres 0045 domain-claims test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	scratch := createScratchDatabase(ctx, t, dsn)
	m, err := newMigrator(scratch)
	require.NoError(t, err)
	defer closeMigrator(m)
	require.NoError(t, m.Migrate(uint(domainClaimsMigrationVersion-1)))

	conn, err := pgx.Connect(ctx, scratch)
	require.NoError(t, err)
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx, `
		INSERT INTO projects (id, storage_scope_id, created_at_ms, updated_at_ms) VALUES ('p', 'scope-p', 0, 0);
		INSERT INTO tenants (id, project_id, created_at_ms, updated_at_ms)
		VALUES ('t-dns', 'p', 0, 0), ('t-email', 'p', 0, 0), ('t-verified', 'p', 0, 0), ('t-old', 'p', 0, 0);
		INSERT INTO domains (id, project_id, tenant_id, domain, verification_method, status, created_at_ms, updated_at_ms)
		VALUES ('d-dns', 'p', 't-dns', 'dns.example.com', 'dns_txt', 'pending', 1, 1),
		       ('d-failed', 'p', 't-dns', 'failed.example.com', 'dns_txt', 'failed', 2, 2),
		       ('d-email', 'p', 't-email', 'email.example.com', 'email', 'pending', 3, 3)`)
	require.NoError(t, err)

	require.NoError(t, m.Migrate(domainClaimsMigrationVersion))
	legacy := map[string]bool{}
	rows, err := conn.Query(ctx, `SELECT id, legacy_txt_challenge FROM domains`)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		var flag bool
		require.NoError(t, rows.Scan(&id, &flag))
		legacy[id] = flag
	}
	require.NoError(t, rows.Err())
	require.Equal(t, map[string]bool{"d-dns": true, "d-failed": true, "d-email": false}, legacy)

	// Contest dns.example.com: an older pending claim, a newer verified one.
	_, err = conn.Exec(ctx, `
		INSERT INTO domains (id, project_id, tenant_id, domain, verification_method, status, created_at_ms, updated_at_ms)
		VALUES ('d-old', 'p', 't-old', 'DNS.example.com', 'dns_txt', 'pending', 0, 0),
		       ('d-verified', 'p', 't-verified', 'dns.example.com', 'dns_txt', 'verified', 5, 5),
		       ('d-email-2', 'p', 't-old', 'email.example.com', 'dns_txt', 'pending', 6, 6)`)
	require.NoError(t, err, "after 0045 tenants may contest a domain")
	_, err = conn.Exec(ctx, `
		INSERT INTO domains (id, project_id, tenant_id, domain, verification_method, status, created_at_ms, updated_at_ms)
		VALUES ('d-verified-2', 'p', 't-dns', 'dns.example.com', 'dns_txt', 'verified', 7, 7)`)
	require.Error(t, err, "one verified row per domain")

	require.NoError(t, m.Migrate(domainClaimsMigrationVersion-1))
	var kept []string
	rows, err = conn.Query(ctx, `SELECT id FROM domains ORDER BY id`)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		kept = append(kept, id)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, []string{"d-email", "d-failed", "d-verified"}, kept,
		"the downgrade keeps the verified claim, else the oldest")
	require.False(t, hasColumn(ctx, t, conn, "domains", "legacy_txt_challenge"))
	_, err = conn.Exec(ctx, `
		INSERT INTO domains (id, project_id, tenant_id, domain, verification_method, status, created_at_ms, updated_at_ms)
		VALUES ('d-again', 'p', 't-old', 'failed.example.com', 'dns_txt', 'pending', 8, 8)`)
	require.Error(t, err, "the downgrade restores one row per domain")
}
