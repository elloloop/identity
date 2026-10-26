package postgres

import (
	"context"
	"fmt"
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

	projectID, err = NewProjectStore(repo, true, nil).createProject(ctx, &Project{StorageScopeID: "scope-mem", Name: "Mem"})
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
	runInvitationLimits(t, dsn)
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
	}, unlimitedInvitations)
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
	}, unlimitedInvitations)
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
	}, unlimitedInvitations)
	require.NoError(t, err)

	// Misses + validation.
	miss, err := is.GetInvitationByTokenHash(ctx, projectID, "no-such")
	require.NoError(t, err)
	require.Nil(t, miss)
	_, err = is.CreateInvitation(ctx, &service.TenantInvitation{ProjectID: projectID, TenantID: tenantID, TokenHash: "h", ExpiresAtMs: 1}, unlimitedInvitations)
	require.ErrorIs(t, err, service.ErrInvalidArgument, "missing email")
	_, err = is.CreateInvitation(ctx, &service.TenantInvitation{ProjectID: projectID, TenantID: tenantID, Email: "x@y.com", ExpiresAtMs: 1}, unlimitedInvitations)
	require.ErrorIs(t, err, service.ErrInvalidArgument, "missing token_hash")
	_, err = is.CreateInvitation(ctx, &service.TenantInvitation{ProjectID: projectID, TenantID: tenantID, Email: "x@y.com", TokenHash: "h"}, unlimitedInvitations)
	require.ErrorIs(t, err, service.ErrInvalidArgument, "missing expires_at_ms")
	require.ErrorIs(t, is.SetInvitationStatus(ctx, "", "id", service.InvitationStatusRevoked, 0), service.ErrInvalidArgument)
}

// runInvitationLimits asserts the per-recipient resend cooldown and the
// per-tenant cap CreateInvitation applies: a refused create writes nothing
// and leaves the open invite pending, both count invitations of any status,
// and each tenant has its own cap.
func runInvitationLimits(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	_, is, projectID, tenantID, _, _ := newMembershipFixture(ctx, t, dsn)
	otherTenant, err := (&TenantStore{pool: is.pool}).CreateTenant(ctx, &service.Tenant{
		ProjectID: projectID, Status: service.TenantStatusClaimed,
	})
	require.NoError(t, err)

	now := nowMs()
	invite := func(tenant, email, tokenHash string, limits service.InvitationLimits) error {
		t.Helper()
		_, err := is.CreateInvitation(ctx, &service.TenantInvitation{
			ProjectID: projectID, TenantID: tenant, Email: email,
			TokenHash: tokenHash, ExpiresAtMs: now + 86_400_000, CreatedAtMs: now,
		}, limits)
		return err
	}
	count := func(tenant string) int {
		t.Helper()
		list, err := is.ListInvitationsForTenant(ctx, projectID, tenant)
		require.NoError(t, err)
		return len(list)
	}

	require.ErrorIs(t, invite(tenantID, "a@acme.com", "lim-0", service.InvitationLimits{}),
		service.ErrInvalidArgument, "a create must be given a cap")

	cooling := service.InvitationLimits{MaxPerTenant: 10, WindowStartMs: now - 3_600_000, ResendCooldownStartMs: now - 60_000}
	require.NoError(t, invite(tenantID, "a@acme.com", "lim-1", cooling))
	require.ErrorIs(t, invite(tenantID, "A@acme.com", "lim-2", cooling), service.ErrInvitationResendTooSoon)
	open, err := is.GetInvitationByTokenHash(ctx, projectID, "lim-1")
	require.NoError(t, err)
	require.Equal(t, service.InvitationStatusPending, open.Status, "a refused resend leaves the open invite pending")
	require.Equal(t, 1, count(tenantID), "a refused resend writes nothing")
	require.NoError(t, invite(otherTenant, "a@acme.com", "lim-3", cooling), "the cooldown is per tenant")

	require.NoError(t, is.SetInvitationStatus(ctx, projectID, open.ID, service.InvitationStatusRevoked, 0))
	require.ErrorIs(t, invite(tenantID, "a@acme.com", "lim-4", cooling), service.ErrInvitationResendTooSoon,
		"revoking the invitation does not reset the cooldown")
	cooled := cooling
	cooled.ResendCooldownStartMs = now + 1
	require.NoError(t, invite(tenantID, "a@acme.com", "lim-5", cooled), "past the cooldown a resend is accepted")

	capped := service.InvitationLimits{MaxPerTenant: 2, WindowStartMs: now - 3_600_000}
	require.ErrorIs(t, invite(tenantID, "b@acme.com", "lim-6", capped), service.ErrInvitationLimited,
		"the revoked invitation still counts toward the cap")
	require.Equal(t, 2, count(tenantID), "a refused create writes nothing")
	require.NoError(t, invite(otherTenant, "b@acme.com", "lim-7", capped), "the cap is per tenant")
	movedOn := capped
	movedOn.WindowStartMs = now + 1
	require.NoError(t, invite(tenantID, "b@acme.com", "lim-8", movedOn), "invitations before the window do not count")
}

// TestInvitationStore_ConcurrentCreatesRespectTheCap: creates for one tenant
// are serialized, so however many race for the last places under the cap,
// exactly that many succeed.
func TestInvitationStore_ConcurrentCreatesRespectTheCap(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping concurrent invitation cap test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	_, is, projectID, tenantID, _, _ := newMembershipFixture(ctx, t, dsn)

	const racers, limit = 8, 3
	limits := service.InvitationLimits{MaxPerTenant: limit, WindowStartMs: nowMs() - 3_600_000}
	errs := make(chan error, racers)
	for i := range racers {
		go func() {
			_, err := is.CreateInvitation(ctx, &service.TenantInvitation{
				ProjectID: projectID, TenantID: tenantID, Email: fmt.Sprintf("racer-%d@acme.com", i),
				TokenHash: fmt.Sprintf("cap-race-%d", i), ExpiresAtMs: nowMs() + 86_400_000,
			}, limits)
			errs <- err
		}()
	}
	refused := 0
	for range racers {
		if err := <-errs; err != nil {
			require.ErrorIs(t, err, service.ErrInvitationLimited)
			refused++
		}
	}
	require.Equal(t, racers-limit, refused)
	list, err := is.ListInvitationsForTenant(ctx, projectID, tenantID)
	require.NoError(t, err)
	require.Len(t, list, limit, "exactly the cap's worth of invitations exist")
}

// unlimitedInvitations holds a create to a cap no test reaches and no
// resend cooldown, for the tests that are about something else.
var unlimitedInvitations = service.InvitationLimits{MaxPerTenant: 1000}

// TestInvitationStore_OneOpenInviteUnderFoldEmail: the store compares the
// canonical address the service gives it under service.FoldEmail, so an
// address differing only in ASCII case replaces the open invite and one
// differing in a non-ASCII letter is another recipient. (Pending invitations
// stored before the service canonicalized are rewritten by migration 0034 —
// TestMigrate_0034CanonicalizesPendingInvitations.)
func TestInvitationStore_OneOpenInviteUnderFoldEmail(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping invitation fold test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	_, is, projectID, tenantID, _, _ := newMembershipFixture(ctx, t, dsn)

	invite := func(email, tokenHash string) {
		t.Helper()
		_, err := is.CreateInvitation(ctx, &service.TenantInvitation{
			ProjectID: projectID, TenantID: tenantID, Email: email,
			TokenHash: tokenHash, ExpiresAtMs: nowMs() + 86_400_000,
		}, unlimitedInvitations)
		require.NoError(t, err)
	}
	status := func(tokenHash string) string {
		t.Helper()
		inv, err := is.GetInvitationByTokenHash(ctx, projectID, tokenHash)
		require.NoError(t, err)
		return inv.Status
	}

	invite("zoé@acme.com", "fold-1")
	invite("ZOé@ACME.com", "fold-2")
	require.Equal(t, service.InvitationStatusRevoked, status("fold-1"), "ASCII case names the same recipient")
	invite("zoÉ@acme.com", "fold-3")
	require.Equal(t, service.InvitationStatusPending, status("fold-2"), "a different non-ASCII letter is another recipient")
	require.Equal(t, service.InvitationStatusPending, status("fold-3"))
}

// TestInvitationStore_ConcurrentCreatesLeaveOneOpenInvite: creates for one
// mailbox are serialized, so however many race, each succeeds by revoking the
// one before it and exactly one stays pending.
func TestInvitationStore_ConcurrentCreatesLeaveOneOpenInvite(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping concurrent invitation test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	_, is, projectID, tenantID, _, _ := newMembershipFixture(ctx, t, dsn)

	const racers = 8
	errs := make(chan error, racers)
	for i := range racers {
		go func() {
			_, err := is.CreateInvitation(ctx, &service.TenantInvitation{
				ProjectID: projectID, TenantID: tenantID, Email: "race@acme.com",
				TokenHash: fmt.Sprintf("race-%d", i), ExpiresAtMs: nowMs() + 86_400_000,
			}, unlimitedInvitations)
			errs <- err
		}()
	}
	for range racers {
		require.NoError(t, <-errs)
	}
	list, err := is.ListInvitationsForTenant(ctx, projectID, tenantID)
	require.NoError(t, err)
	pending := 0
	for _, inv := range list {
		if inv.Status == service.InvitationStatusPending {
			pending++
		}
	}
	require.Len(t, list, racers)
	require.Equal(t, 1, pending, "one open invite per mailbox, however the creates interleave")
}

// TestMembershipStore_GrantNeverLowersARole: a grant makes an active member
// at its role, promotes a lower one, re-activates an ended one at the grant's
// role, and leaves an active membership at that role or above unchanged —
// even against a concurrent grant of a lower role.
func TestMembershipStore_GrantNeverLowersARole(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping membership grant test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	ms, _, projectID, tenantID, user1, user2 := newMembershipFixture(ctx, t, dsn)

	grant := func(userID, role, source string) *service.TenantMembership {
		t.Helper()
		m, err := ms.GrantMembership(ctx, &service.TenantMembership{
			ProjectID: projectID, TenantID: tenantID, UserID: userID, Role: role, Source: source,
		})
		require.NoError(t, err)
		return m
	}

	m := grant(user1, service.RoleOwner, service.MembershipSourceAdded)
	require.Equal(t, service.RoleOwner, m.Role)
	require.Equal(t, service.MembershipStatusActive, m.Status)

	kept := grant(user1, service.RoleMember, service.MembershipSourceInvited)
	require.Equal(t, service.RoleOwner, kept.Role, "a lower grant never demotes")
	require.Equal(t, service.MembershipSourceAdded, kept.Source, "nor rewrites the membership")
	require.Equal(t, m.ID, kept.ID)
	require.Equal(t, service.RoleOwner, grant(user1, service.RoleOwner, service.MembershipSourceInvited).Role)

	require.Equal(t, service.RoleMember, grant(user2, service.RoleMember, service.MembershipSourceInvited).Role)
	promoted := grant(user2, service.RoleAdmin, service.MembershipSourceInvited)
	require.Equal(t, service.RoleAdmin, promoted.Role, "a higher grant promotes")

	_, err := ms.UpsertMembership(ctx, &service.TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: user2, Role: service.RoleOwner,
		Source: service.MembershipSourceAdded, Status: service.MembershipStatusInactive,
	})
	require.NoError(t, err)
	rejoined := grant(user2, service.RoleMember, service.MembershipSourceInvited)
	require.Equal(t, service.MembershipStatusActive, rejoined.Status)
	require.Equal(t, service.RoleMember, rejoined.Role, "an ended membership comes back at the grant's role")

	_, err = ms.GrantMembership(ctx, &service.TenantMembership{ProjectID: projectID, TenantID: tenantID})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	_, err = ms.GrantMembership(ctx, nil)
	require.Error(t, err)

	// However an owner grant and member grants interleave, the owner stays.
	require.NoError(t, ms.RemoveMembership(ctx, projectID, tenantID, user2))
	const racers = 8
	errs := make(chan error, racers)
	for i := range racers {
		role := service.RoleMember
		if i == racers/2 {
			role = service.RoleOwner
		}
		go func() {
			_, err := ms.GrantMembership(ctx, &service.TenantMembership{
				ProjectID: projectID, TenantID: tenantID, UserID: user2, Role: role, Source: service.MembershipSourceInvited,
			})
			errs <- err
		}()
	}
	for range racers {
		require.NoError(t, <-errs)
	}
	final, err := ms.GetMembership(ctx, projectID, tenantID, user2)
	require.NoError(t, err)
	require.Equal(t, service.RoleOwner, final.Role)
}

// TestInvitationStore_InviterAndRecipientLimits: the per-inviter cap counts
// one person's invitations from every tenant, the per-recipient cap one
// address's from every tenant of the project, and a zero cap is off.
func TestInvitationStore_InviterAndRecipientLimits(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping invitation sender limits test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	_, is, projectID, tenantA, user1, user2 := newMembershipFixture(ctx, t, dsn)
	newTenant := func() string {
		t.Helper()
		id, err := (&TenantStore{pool: is.pool}).CreateTenant(ctx, &service.Tenant{ProjectID: projectID, Status: service.TenantStatusClaimed})
		require.NoError(t, err)
		return id
	}
	tenantB, tenantC := newTenant(), newTenant()

	now := nowMs()
	n := 0
	invite := func(tenant, inviter, email string, limits service.InvitationLimits) error {
		t.Helper()
		n++
		_, err := is.CreateInvitation(ctx, &service.TenantInvitation{
			ProjectID: projectID, TenantID: tenant, Email: email, InvitedBy: inviter,
			TokenHash: fmt.Sprintf("sender-%d", n), ExpiresAtMs: now + 86_400_000, CreatedAtMs: now,
		}, limits)
		return err
	}
	window := now - 3_600_000

	perInviter := service.InvitationLimits{MaxPerTenant: 100, WindowStartMs: window, MaxPerInviter: 2}
	require.NoError(t, invite(tenantA, user1, "i1@acme.com", perInviter))
	require.NoError(t, invite(tenantB, user1, "i2@acme.com", perInviter))
	require.ErrorIs(t, invite(tenantC, user1, "i3@acme.com", perInviter), service.ErrInviterLimited,
		"the cap spans the inviter's tenants")
	require.NoError(t, invite(tenantC, user2, "i3@acme.com", perInviter), "each inviter has their own cap")
	later := perInviter
	later.WindowStartMs = now + 1
	require.NoError(t, invite(tenantC, user1, "i4@acme.com", later), "invitations before the window do not count")
	off := perInviter
	off.MaxPerInviter = 0
	require.NoError(t, invite(tenantC, user1, "i5@acme.com", off), "a zero cap is off")

	perRecipient := service.InvitationLimits{MaxPerTenant: 100, WindowStartMs: window, MaxPerRecipient: 2}
	require.NoError(t, invite(tenantA, user1, "r@acme.com", perRecipient))
	require.NoError(t, invite(tenantB, user2, "R@acme.com", perRecipient))
	require.ErrorIs(t, invite(tenantC, user2, "r@ACME.com", perRecipient), service.ErrInvitationRecipientLimited,
		"the cap spans the project's tenants and the address's case")
	require.NoError(t, invite(tenantC, user2, "other@acme.com", perRecipient), "each address has its own cap")
	list, err := is.ListInvitationsForTenant(ctx, projectID, tenantC)
	require.NoError(t, err)
	for _, inv := range list {
		require.NotEqual(t, "r@acme.com", inv.Email, "a refused invitation writes nothing")
	}
}
