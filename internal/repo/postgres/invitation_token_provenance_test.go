package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// TestInvitationStore_TokenOnlyInEmail: CreateInvitation stores whether an
// invitation's token went only into its email as it is given, and every read
// hands it back: by token, as an open invitation by token or by address,
// among the tenant's invitations, and from a revoke. It does not decide
// whether an invitation is open. A row written without it, as by a server
// older than migration 0067, reads false.
func TestInvitationStore_TokenOnlyInEmail(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping invitation token provenance test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	ms, is, projectID, tenantID, _, _ := newMembershipFixture(ctx, t, dsn)
	people, err := New(ctx, Config{DSN: dsn, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: projectID})
	require.NoError(t, err)
	t.Cleanup(people.Close)
	created := time.Now()
	owner, err := people.CreateUser(ctx, &service.User{Email: "owner@acme.com", Status: service.StatusActive, CreatedAt: created, UpdatedAt: created})
	require.NoError(t, err)
	_, err = ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: owner,
		Source: service.MembershipSourceAdded, Role: service.RoleOwner, Status: service.MembershipStatusActive,
	})
	require.NoError(t, err)

	expires := nowMs() + time.Hour.Milliseconds()
	invite := func(email, tokenHash string, onlyInEmail bool) string {
		t.Helper()
		id, err := is.CreateInvitation(ctx, &service.TenantInvitation{
			ProjectID: projectID, TenantID: tenantID, Email: email, InvitedBy: owner,
			TokenHash: tokenHash, ExpiresAtMs: expires, TokenOnlyInEmail: onlyInEmail,
		}, unlimitedInvitations)
		require.NoError(t, err)
		return id
	}
	emailed := invite("emailed@acme.com", "provenance-emailed", true)
	handedOut := invite("handed@acme.com", "provenance-handed", false)

	for tokenHash, want := range map[string]bool{"provenance-emailed": true, "provenance-handed": false} {
		got, err := is.GetInvitationByTokenHash(ctx, projectID, tokenHash)
		require.NoError(t, err)
		require.Equal(t, want, got.TokenOnlyInEmail, tokenHash)
		open, err := is.OpenInvitationForToken(ctx, projectID, tokenHash, nowMs())
		require.NoError(t, err)
		require.NotNil(t, open, "%s: the flag does not decide whether an invitation is open", tokenHash)
		require.Equal(t, want, open.TokenOnlyInEmail, tokenHash)
	}
	for addr, want := range map[string]bool{"emailed@acme.com": true, "handed@acme.com": false} {
		open, err := is.OpenInvitationForEmail(ctx, projectID, addr, nowMs())
		require.NoError(t, err)
		require.NotNil(t, open, addr)
		require.Equal(t, want, open.TokenOnlyInEmail, addr)
	}
	listed, err := is.ListInvitationsForTenant(ctx, projectID, tenantID)
	require.NoError(t, err)
	flags := map[string]bool{}
	for _, inv := range listed {
		flags[inv.ID] = inv.TokenOnlyInEmail
	}
	require.Equal(t, map[string]bool{emailed: true, handedOut: false}, flags)
	revoked, changed, err := is.RevokeInvitation(ctx, projectID, tenantID, emailed)
	require.NoError(t, err)
	require.True(t, changed)
	require.True(t, revoked.TokenOnlyInEmail, "a revoke keeps where the token went")

	raw, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	_, err = raw.Exec(ctx, `
		INSERT INTO tenant_invitations (id, project_id, tenant_id, token_hash, email, invited_by, role, status, expires_at_ms, created_at_ms)
		VALUES ('inv-unrecorded', $1, $2, 'provenance-unrecorded', 'older@acme.com', $3, 'member', 'pending', $4, $5)`,
		projectID, tenantID, owner, expires, nowMs())
	require.NoError(t, err)
	unrecorded, err := is.GetInvitationByTokenHash(ctx, projectID, "provenance-unrecorded")
	require.NoError(t, err)
	require.False(t, unrecorded.TokenOnlyInEmail, "a row that does not say where its token went reads as one whose token may have gone anywhere")
}
