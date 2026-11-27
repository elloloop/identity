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
