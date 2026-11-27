package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestInvitationStore_ManagedAccountsAmong: of the ids asked about, exactly
// the accounts the tenant manages are reported; a personal account, another
// tenant's managed account and an unknown id are not.
func TestInvitationStore_ManagedAccountsAmong(t *testing.T) {
	dsn := memberRoleDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	store := NewInvitationStore(f.accounts)
	now := time.Now()
	managed := func(email, tenantID string) string {
		id, err := f.accounts.CreateUser(ctx, &service.User{
			Email: email, Status: service.StatusInvited, ManagedByTenantID: tenantID, SetupEpoch: 1,
			CreatedAt: now, UpdatedAt: now,
		})
		require.NoError(t, err)
		return id
	}
	ann := managed("ann@acme.com", f.tenantID)
	elsewhere := managed("bob@other.example.com", "another-tenant")

	got, err := store.ManagedAccountsAmong(ctx, f.projectID, f.tenantID, []string{ann, f.user, elsewhere, "no-such-user"})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{ann: true}, got)

	got, err = store.ManagedAccountsAmong(ctx, f.projectID, f.tenantID, nil)
	require.NoError(t, err)
	require.Empty(t, got)

	_, err = store.ManagedAccountsAmong(ctx, "", f.tenantID, []string{ann})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
}

// annSetup asks for a managed account at username@acme.com of f's tenant,
// its link sent to delivery, issued by by with role.
func (f *joinFixture) annSetup(username, delivery, by, role string, limits service.InvitationLimits, maxPerDelivery int) service.ManagedSetup {
	if limits.MaxPerTenant == 0 {
		limits.MaxPerTenant = 100
	}
	return service.ManagedSetup{
		ProjectID: f.projectID, TenantID: f.tenantID, Address: username + "@acme.com", Domain: "acme.com",
		DisplayName: username, DeliveryEmail: delivery, Role: role, InvitedBy: by,
		TokenHash: username + "-link", ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(),
		Limits: limits, MaxPerDeliveryEmail: maxPerDelivery,
	}
}

// TestInvitationStore_SetUpLinksPerDeliveryAddress: the resend cooldown and
// the per-delivery cap both apply to the address a set-up link is sent to,
// across accounts.
func TestInvitationStore_SetUpLinksPerDeliveryAddress(t *testing.T) {
	dsn := memberRoleDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	store := NewInvitationStore(f.accounts)
	hourAgo := time.Now().Add(-time.Hour).UnixMilli()

	_, err := store.CreateManagedSetup(ctx, f.annSetup("ann", "home@example.net", f.other, service.RoleMember, service.InvitationLimits{ResendCooldownStartMs: hourAgo}, 0))
	require.NoError(t, err)
	_, err = store.CreateManagedSetup(ctx, f.annSetup("bob", "home@example.net", f.other, service.RoleMember, service.InvitationLimits{ResendCooldownStartMs: hourAgo}, 0))
	require.ErrorIs(t, err, service.ErrInvitationResendTooSoon, "a second link to one delivery address inside the cooldown")

	_, err = store.CreateManagedSetup(ctx, f.annSetup("cat", "home@example.net", f.other, service.RoleMember, service.InvitationLimits{WindowStartMs: hourAgo}, 1))
	require.ErrorIs(t, err, service.ErrManagedResetLimited, "past the per-delivery cap")
	_, err = store.CreateManagedSetup(ctx, f.annSetup("dan", "work@example.net", f.other, service.RoleMember, service.InvitationLimits{WindowStartMs: hourAgo}, 1))
	require.NoError(t, err, "another delivery address keeps its own count")
}

// TestInvitationStore_OnlyAnOwnerRevokesAnOwnersLink: an admin may revoke a
// member's set-up link but not an owner's, nor any link of an account whose
// pending link is an owner's.
func TestInvitationStore_OnlyAnOwnerRevokesAnOwnersLink(t *testing.T) {
	dsn := memberRoleDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newJoinFixture(ctx, t, dsn)
	store := NewInvitationStore(f.accounts)
	admin := f.account(ctx, t, "admin@acme.com")
	f.grant(ctx, t, admin, service.RoleAdmin)

	owners, err := store.CreateManagedSetup(ctx, f.annSetup("own", "own@example.net", f.other, service.RoleOwner, service.InvitationLimits{}, 0))
	require.NoError(t, err)
	_, err = store.RevokeManagedSetup(ctx, f.projectID, f.tenantID, owners.Invitation.ID, admin)
	require.ErrorIs(t, err, service.ErrPermissionDenied, "an admin revoking an owner's link")
	revoked, err := store.RevokeManagedSetup(ctx, f.projectID, f.tenantID, owners.Invitation.ID, f.other)
	require.NoError(t, err, "an owner revokes it")
	require.NotNil(t, revoked.DeletedUser)

	members, err := store.CreateManagedSetup(ctx, f.annSetup("mem", "mem@example.net", admin, service.RoleMember, service.InvitationLimits{}, 0))
	require.NoError(t, err)
	_, err = store.RevokeManagedSetup(ctx, f.projectID, f.tenantID, members.Invitation.ID, admin)
	require.NoError(t, err, "an admin revokes a member's link")
}
