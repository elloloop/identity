package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// newMembershipFixture migrates a Postgres at dsn and seeds a project, a
// claimed tenant, and two users (the FK targets). It returns the membership
// and invitation stores plus the seeded ids. The repository is closed on
// cleanup.
func newMembershipFixture(ctx context.Context, t *testing.T, dsn string) (ms *MembershipStore, is *InvitationStore, projectID, tenantID, user1, user2 string) {
	t.Helper()
	repo, err := New(ctx, Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		ProjectID:   "control-plane",
	})
	require.NoError(t, err)
	t.Cleanup(repo.Close)

	// The repo binds to the "control-plane" project; the users it creates
	// carry project_id="control-plane", which must exist for the FK added in
	// migration 0015.
	seedProject(ctx, t, repo, "control-plane")

	projectID, err = NewProjectStore(repo, true).createProject(ctx, &Project{StorageScopeID: "scope-mem", Name: "Mem"})
	require.NoError(t, err)
	tenantID, err = NewTenantStore(repo).CreateTenant(ctx, &service.Tenant{
		ProjectID: projectID, Status: service.TenantStatusClaimed,
	})
	require.NoError(t, err)

	now := time.Now()
	user1, err = repo.CreateUser(ctx, &service.User{Email: "u1@acme.com", Status: "active", CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	user2, err = repo.CreateUser(ctx, &service.User{Email: "u2@acme.com", Status: "active", CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)

	return NewMembershipStore(repo), NewInvitationStore(repo), projectID, tenantID, user1, user2
}

// TestMembershipStore_Smoke runs the membership + invitation store
// round-trips against a live Postgres pointed to by GATEWAY_TEST_POSTGRES_DSN
// (CI's coverage job), skipping when unset.
func TestMembershipStore_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping membership store smoke test")
	}
	runMembershipSmoke(t, dsn)
}

func runMembershipSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))
	ms, is, projectID, tenantID, user1, user2 := newMembershipFixture(ctx, t, dsn)

	// ── memberships ─────────────────────────────────────────────────
	id1, err := ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: user1,
		Source: service.MembershipSourceDomain,
	})
	require.NoError(t, err)
	require.NotEmpty(t, id1)

	m, err := ms.GetMembership(ctx, projectID, tenantID, user1)
	require.NoError(t, err)
	require.NotNil(t, m)
	require.Equal(t, service.MembershipSourceDomain, m.Source)
	require.Equal(t, service.RoleMember, m.Role, "role defaults to member")
	require.Equal(t, service.MembershipStatusActive, m.Status, "status defaults to active")

	// Upsert same (project,tenant,user) → update in place, same id.
	id1b, err := ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: user1,
		Source: service.MembershipSourceAdded, Role: service.RoleOwner,
	})
	require.NoError(t, err)
	require.Equal(t, id1, id1b, "upsert keeps the row id")
	m, err = ms.GetMembership(ctx, projectID, tenantID, user1)
	require.NoError(t, err)
	require.Equal(t, service.RoleOwner, m.Role)

	// Second user → second membership.
	_, err = ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: user2,
	})
	require.NoError(t, err)

	forUser, err := ms.ListMembershipsForUser(ctx, projectID, user1)
	require.NoError(t, err)
	require.Len(t, forUser, 1)
	forTenant, err := ms.ListMembershipsForTenant(ctx, projectID, tenantID)
	require.NoError(t, err)
	require.Len(t, forTenant, 2)

	// Remove + miss + validation.
	require.NoError(t, ms.RemoveMembership(ctx, projectID, tenantID, user2))
	gone, err := ms.GetMembership(ctx, projectID, tenantID, user2)
	require.NoError(t, err)
	require.Nil(t, gone)
	require.NoError(t, ms.RemoveMembership(ctx, projectID, tenantID, "no-such-user"), "removing an absent membership is a no-op")
	_, err = ms.UpsertMembership(ctx, &service.TenantMembership{ProjectID: projectID})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	require.ErrorIs(t, ms.RemoveMembership(ctx, "", tenantID, user1), service.ErrInvalidArgument)

	// ── invitations: one-open-invite via atomic revoke-then-insert ──
	_, err = is.CreateInvitation(ctx, &service.TenantInvitation{
		ProjectID: projectID, TenantID: tenantID, Email: "new@acme.com",
		TokenHash: "hash-1", InvitedBy: user1, ExpiresAtMs: nowMs() + 86_400_000,
	})
	require.NoError(t, err)

	inv1, err := is.GetInvitationByTokenHash(ctx, projectID, "hash-1")
	require.NoError(t, err)
	require.NotNil(t, inv1)
	require.Equal(t, service.InvitationStatusPending, inv1.Status)
	require.Equal(t, service.RoleMember, inv1.Role, "role defaults to member")

	// A second invite for the SAME email revokes the first and becomes the
	// only pending one.
	_, err = is.CreateInvitation(ctx, &service.TenantInvitation{
		ProjectID: projectID, TenantID: tenantID, Email: "NEW@acme.com", // case-insensitive match
		TokenHash: "hash-2", InvitedBy: user1, Role: service.RoleAdmin, ExpiresAtMs: nowMs() + 86_400_000,
	})
	require.NoError(t, err)

	old, err := is.GetInvitationByTokenHash(ctx, projectID, "hash-1")
	require.NoError(t, err)
	require.Equal(t, service.InvitationStatusRevoked, old.Status, "the prior open invite is revoked")
	cur, err := is.GetInvitationByTokenHash(ctx, projectID, "hash-2")
	require.NoError(t, err)
	require.Equal(t, service.InvitationStatusPending, cur.Status)
	require.Equal(t, service.RoleAdmin, cur.Role)

	// Exactly one pending invite for that email survives.
	list, err := is.ListInvitationsForTenant(ctx, projectID, tenantID)
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, "hash-2", list[0].TokenHash, "newest first")
	pending := 0
	for _, v := range list {
		if v.Status == service.InvitationStatusPending {
			pending++
		}
	}
	require.Equal(t, 1, pending, "one open invite per (project, tenant, email)")

	// Accept it.
	require.NoError(t, is.SetInvitationStatus(ctx, projectID, cur.ID, service.InvitationStatusAccepted, 0))
	cur, err = is.GetInvitationByTokenHash(ctx, projectID, "hash-2")
	require.NoError(t, err)
	require.Equal(t, service.InvitationStatusAccepted, cur.Status)
	require.NotZero(t, cur.AcceptedAtMs, "accept stamps accepted_at_ms")

	// A different email is independent.
	_, err = is.CreateInvitation(ctx, &service.TenantInvitation{
		ProjectID: projectID, TenantID: tenantID, Email: "other@acme.com",
		TokenHash: "hash-3", ExpiresAtMs: nowMs() + 86_400_000,
	})
	require.NoError(t, err)

	// Misses + validation.
	miss, err := is.GetInvitationByTokenHash(ctx, projectID, "no-such")
	require.NoError(t, err)
	require.Nil(t, miss)
	_, err = is.CreateInvitation(ctx, &service.TenantInvitation{ProjectID: projectID, TenantID: tenantID, TokenHash: "h", ExpiresAtMs: 1})
	require.ErrorIs(t, err, service.ErrInvalidArgument, "missing email")
	_, err = is.CreateInvitation(ctx, &service.TenantInvitation{ProjectID: projectID, TenantID: tenantID, Email: "x@y.com", ExpiresAtMs: 1})
	require.ErrorIs(t, err, service.ErrInvalidArgument, "missing token_hash")
	_, err = is.CreateInvitation(ctx, &service.TenantInvitation{ProjectID: projectID, TenantID: tenantID, Email: "x@y.com", TokenHash: "h"})
	require.ErrorIs(t, err, service.ErrInvalidArgument, "missing expires_at_ms")
	require.ErrorIs(t, is.SetInvitationStatus(ctx, "", "id", service.InvitationStatusRevoked, 0), service.ErrInvalidArgument)
}
