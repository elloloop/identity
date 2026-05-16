//go:build realpostgres

// Real-Postgres seed test. Drives the postgres repository against a
// live Postgres server (started by docker compose locally or by the
// GitHub Actions service container in CI).
//
// Gated behind the `realpostgres` build tag so it doesn't run during
// the default unit test job.
//
// If GATEWAY_POSTGRES_DSN is unset the test skips so a developer
// running `go test -tags=realpostgres` without compose up does not
// see a confusing connection error.

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/repo/postgres"
	"github.com/elloloop/identity/internal/service"
)

func TestRealPostgres_RepositorySmoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN unset — skipping realpostgres smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := postgres.Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		TenantID:    "realpg-tenant",
	}
	repo, err := postgres.New(ctx, cfg)
	require.NoError(t, err)

	// Round-trip a user to prove the wire and migrations both work
	// against a real Postgres process.
	now := time.Now()
	id, err := repo.CreateUser(ctx, &service.User{
		Email:     "rp-" + time.Now().Format("150405.000000") + "@example.com",
		Name:      "RealPostgres",
		Role:      "member",
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	})
	require.NoError(t, err)
	require.NotEmpty(t, id)

	got, err := repo.GetUser(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
}

// TestRealPostgres_Organization exercises the mode=multi Organization
// surface end-to-end against a live Postgres. The default-tag
// conformance suite under internal/repo/postgres/ covers in-process
// runs; this is the integration mirror that the realpostgres CI job
// invokes to catch migrations / scoping / JOIN regressions.
func TestRealPostgres_Organization(t *testing.T) {
	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN unset — skipping realpostgres organization")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tenantID := "realpg-org-" + time.Now().Format("150405.000000")
	cfg := postgres.Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		TenantID:    tenantID,
	}
	repo, err := postgres.New(ctx, cfg)
	require.NoError(t, err)

	now := time.Now()
	ownerID, err := repo.CreateUser(ctx, &service.User{
		Email: "owner-" + time.Now().Format("150405.000000") + "@example.com",
		Name:  "Owner", Role: "admin", Status: "active",
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	memberID, err := repo.CreateUser(ctx, &service.User{
		Email: "member-" + time.Now().Format("150405.000000") + "@example.com",
		Name:  "Member", Role: "member", Status: "active",
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	slug := "acme-" + time.Now().Format("150405.000000")
	orgID, err := repo.CreateOrganization(ctx, &service.Organization{
		Slug: slug, DisplayName: "Acme Corp", OwnerUserID: ownerID,
		CreatedAtMs: now.UnixMilli(), UpdatedAtMs: now.UnixMilli(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, orgID)

	// Duplicate slug → ErrAlreadyExists via wrapPgErr.
	_, err = repo.CreateOrganization(ctx, &service.Organization{
		Slug: slug, DisplayName: "Doppelganger", OwnerUserID: memberID,
		CreatedAtMs: now.UnixMilli(), UpdatedAtMs: now.UnixMilli(),
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists)

	got, err := repo.GetOrganization(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, slug, got.Slug)

	bySlug, err := repo.GetOrganizationBySlug(ctx, slug)
	require.NoError(t, err)
	require.NotNil(t, bySlug)
	require.Equal(t, orgID, bySlug.ID)

	_, err = repo.AddOrganizationMember(ctx, &service.OrganizationMembership{
		OrganizationID: orgID, UserID: ownerID, Role: "admin", CreatedAtMs: now.UnixMilli(),
	})
	require.NoError(t, err)
	_, err = repo.AddOrganizationMember(ctx, &service.OrganizationMembership{
		OrganizationID: orgID, UserID: memberID, Role: "member", CreatedAtMs: now.UnixMilli(),
	})
	require.NoError(t, err)
	_, err = repo.AddOrganizationMember(ctx, &service.OrganizationMembership{
		OrganizationID: orgID, UserID: ownerID, Role: "admin", CreatedAtMs: now.UnixMilli(),
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists)

	memberOrgs, err := repo.ListOrganizationsForUser(ctx, memberID)
	require.NoError(t, err)
	require.Len(t, memberOrgs, 1)
	require.Equal(t, orgID, memberOrgs[0].ID)
}
