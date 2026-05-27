//go:build realentdb

// Real-EntDB seed test for the Organization repository surface
// landed by #93 slice 1 (mode=multi foundation). Drives the typed
// CreateOrganization / GetOrganization / GetOrganizationBySlug /
// AddOrganizationMember / ListOrganizationsForUser methods against
// a live EntDB gRPC server.
//
// CI runs this under the `realentdb` build tag against the docker-
// compose-managed entdb. Locally:
//
//	make services-up
//	GATEWAY_ENTDB_ADDRESS=localhost:50051 \
//	    go test -tags=realentdb ./tests/integration/...
//
// If GATEWAY_ENTDB_ADDRESS is unset the test skips so a developer
// running the suite without compose up does not see a confusing
// connection error.

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/repo/entdb"
	"github.com/elloloop/identity/internal/repo/entdb/entclient"
	"github.com/elloloop/identity/internal/service"
)

func TestRealEntDB_Organization(t *testing.T) {
	addr := os.Getenv("GATEWAY_ENTDB_ADDRESS")
	if addr == "" {
		t.Skip("GATEWAY_ENTDB_ADDRESS unset — skipping realentdb organisation")
	}

	client, err := entclient.New(addr)
	require.NoError(t, err)
	require.NoError(t, client.Connect(context.Background()))
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tenantID := fmt.Sprintf("realentdb-org-%d", time.Now().UnixNano())
	ensureRealEntDBTenant(t, client, tenantID)
	repo := entdb.NewRepository(client, tenantID)
	now := time.Now()

	ownerEmail := fmt.Sprintf("owner-%d@example.com", now.UnixNano())
	ownerID, err := repo.CreateUser(ctx, &service.User{
		Email: ownerEmail, Name: "Owner", Role: "admin", Status: "active",
		PasswordHash: "h", CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	memberEmail := fmt.Sprintf("member-%d@example.com", now.UnixNano())
	memberID, err := repo.CreateUser(ctx, &service.User{
		Email: memberEmail, Name: "Member", Role: "member", Status: "active",
		PasswordHash: "h", CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	slug := fmt.Sprintf("acme-%d", now.UnixNano())
	orgID, err := repo.CreateOrganization(ctx, &service.Organization{
		Slug: slug, DisplayName: "Acme Corp", OwnerUserID: ownerID,
		CreatedAtMs: now.UnixMilli(), UpdatedAtMs: now.UnixMilli(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, orgID)

	got, err := repo.GetOrganization(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "Acme Corp", got.DisplayName)
	require.Equal(t, ownerID, got.OwnerUserID)

	bySlug, err := repo.GetOrganizationBySlug(ctx, slug)
	require.NoError(t, err)
	require.NotNil(t, bySlug)
	require.Equal(t, orgID, bySlug.ID)

	// Duplicate slug must surface as ErrAlreadyExists.
	_, err = repo.CreateOrganization(ctx, &service.Organization{
		Slug: slug, DisplayName: "Doppelganger", OwnerUserID: memberID,
		CreatedAtMs: now.UnixMilli(), UpdatedAtMs: now.UnixMilli(),
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists)

	_, err = repo.AddOrganizationMember(ctx, &service.OrganizationMembership{
		OrganizationID: orgID, UserID: ownerID, Role: "admin",
		CreatedAtMs: now.UnixMilli(),
	})
	require.NoError(t, err)
	_, err = repo.AddOrganizationMember(ctx, &service.OrganizationMembership{
		OrganizationID: orgID, UserID: memberID, Role: "member",
		CreatedAtMs: now.UnixMilli(),
	})
	require.NoError(t, err)

	// Duplicate membership must surface as ErrAlreadyExists.
	_, err = repo.AddOrganizationMember(ctx, &service.OrganizationMembership{
		OrganizationID: orgID, UserID: ownerID, Role: "admin",
		CreatedAtMs: now.UnixMilli(),
	})
	require.ErrorIs(t, err, service.ErrAlreadyExists)

	memberOrgs, err := repo.ListOrganizationsForUser(ctx, memberID)
	require.NoError(t, err)
	require.Len(t, memberOrgs, 1)
	require.Equal(t, orgID, memberOrgs[0].ID)
}
