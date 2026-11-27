package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// managedFixture is joinFixture's tenant (owner other, verified domain
// acme.com, personal account user on it) with its invitation store, for the
// managed-account writes.
type managedFixture struct {
	*joinFixture
	is *InvitationStore
}

func newManagedFixture(t *testing.T) (context.Context, *managedFixture) {
	t.Helper()
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping managed account test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	f := newJoinFixture(ctx, t, dsn)
	return ctx, &managedFixture{joinFixture: f, is: &InvitationStore{pool: f.ms.pool}}
}

var managedTokenSeq atomic.Int64

func managedToken() string {
	return fmt.Sprintf("setup-token-%d", managedTokenSeq.Add(1))
}

func generousLimits() service.InvitationLimits {
	return service.InvitationLimits{MaxPerTenant: 1000, MaxPerInviter: 1000, MaxPerRecipient: 1000}
}

// setup is a set-up request for address on acme.com by by, sent to
// delivery, with role member.
func (f *managedFixture) setup(address, delivery, by string) service.ManagedSetup {
	return service.ManagedSetup{
		ProjectID: f.projectID, TenantID: f.tenantID, Address: address, Domain: "acme.com",
		DisplayName: "Ann Example", DeliveryEmail: delivery, Role: service.RoleMember, InvitedBy: by,
		TokenHash: managedToken(), ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(), Limits: generousLimits(),
	}
}

func (f *managedFixture) create(ctx context.Context, t *testing.T, s service.ManagedSetup) *service.ManagedSetupIssued {
	t.Helper()
	issued, err := f.is.CreateManagedSetup(ctx, s)
	require.NoError(t, err)
	return issued
}

func (f *managedFixture) complete(ctx context.Context, link *service.TenantInvitation) (*service.ManagedSetupCompleted, error) {
	return f.is.CompleteManagedSetup(ctx, service.ManagedSetupCompletion{ProjectID: f.projectID, InvitationID: link.ID, TokenHash: link.TokenHash, PasswordHash: "hash-of-chosen-password"})
}

// setUpAccount creates ann@acme.com as a managed account with role and sets
// it up, returning its id.
func (f *managedFixture) setUpAccount(ctx context.Context, t *testing.T, role string) string {
	t.Helper()
	s := f.setup("ann@acme.com", "ann.home@example.com", f.other)
	s.Role = role
	issued := f.create(ctx, t, s)
	_, err := f.complete(ctx, issued.Invitation)
	require.NoError(t, err)
	return issued.User.ID
}

func (f *managedFixture) readUser(ctx context.Context, t *testing.T, id string) *service.User {
	t.Helper()
	u, err := f.accounts.GetUser(ctx, id)
	require.NoError(t, err)
	return u
}

func (f *managedFixture) invitation(ctx context.Context, t *testing.T, inv *service.TenantInvitation) *service.TenantInvitation {
	t.Helper()
	got, err := f.is.GetInvitationByTokenHash(ctx, f.projectID, inv.TokenHash)
	require.NoError(t, err)
	return got
}

func (f *managedFixture) membership(ctx context.Context, t *testing.T, userID string) *service.TenantMembership {
	t.Helper()
	m, err := f.ms.GetMembership(ctx, f.projectID, f.tenantID, userID)
	require.NoError(t, err)
	return m
}

// signIn gives userID a live session and refresh token, and returns the
// session's id.
func (f *managedFixture) signIn(ctx context.Context, t *testing.T, userID string) string {
	t.Helper()
	sid := "sid-" + managedToken()
	_, err := f.accounts.CreateSession(ctx, &service.SessionRecord{SID: sid, UserID: userID, CreatedAtMs: time.Now().UnixMilli()})
	require.NoError(t, err)
	_, err = f.accounts.CreateRefreshToken(ctx, &service.RefreshTokenRecord{TokenHash: "rt-" + sid, UserID: userID, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), CreatedAt: time.Now().UnixMilli()})
	require.NoError(t, err)
	return sid
}

func (f *managedFixture) sessionLive(ctx context.Context, t *testing.T, sid string) bool {
	t.Helper()
	s, err := f.accounts.GetSessionBySid(ctx, sid)
	require.NoError(t, err)
	return s != nil && s.RevokedAtMs == 0
}

func (f *managedFixture) refreshTokens(ctx context.Context, t *testing.T, userID string) int {
	t.Helper()
	var n int
	require.NoError(t, f.accounts.pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE project_id = $1 AND user_id = $2`, f.projectID, userID).Scan(&n))
	return n
}

// agentOf creates an agent account userID owns.
func (f *managedFixture) agentOf(ctx context.Context, t *testing.T, userID string) string {
	t.Helper()
	now := time.Now()
	id, err := f.accounts.CreateUser(ctx, &service.User{Name: "Helper", Status: service.StatusActive, Kind: service.UserKindAgent, OwnerUserID: userID, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	return id
}

// TestManagedSetup_CreateResendComplete: a new managed account is invited,
// unverified and owned by the tenant, with one pending link that no ordinary
// invitation read returns; a resend bumps the epoch and replaces the link;
// only the current link sets the account up, once.
func TestManagedSetup_CreateResendComplete(t *testing.T) {
	ctx, f := newManagedFixture(t)

	first := f.create(ctx, t, f.setup("ann@acme.com", "ann.home@example.com", f.other))
	require.True(t, first.Created)
	assert.Empty(t, first.PreviousDeliveryEmail)
	account := f.readUser(ctx, t, first.User.ID)
	assert.Equal(t, "ann@acme.com", account.Email)
	assert.Equal(t, "Ann Example", account.Name)
	assert.Equal(t, service.StatusInvited, account.Status)
	assert.Equal(t, f.tenantID, account.ManagedByTenantID)
	assert.Equal(t, int64(1), account.SetupEpoch)
	assert.Zero(t, account.SetUpAtMs)
	assert.False(t, account.EmailVerified)
	assert.Empty(t, account.PasswordHash)
	assert.Empty(t, account.Username)

	link := first.Invitation
	assert.Equal(t, service.InvitationStatusPending, link.Status)
	assert.Equal(t, account.ID, link.UserID)
	assert.Equal(t, "ann@acme.com", link.Email)
	assert.Equal(t, "ann.home@example.com", link.DeliveryEmail)
	assert.Equal(t, int64(1), link.SetupEpoch)
	assert.True(t, link.TokenOnlyInEmail)
	assert.True(t, link.IsManagedSetup())

	open, err := f.is.OpenInvitationForEmail(ctx, f.projectID, "ann@acme.com", time.Now().UnixMilli())
	require.NoError(t, err)
	assert.Nil(t, open, "a set-up link is never an open invitation")
	open, err = f.is.OpenInvitationForToken(ctx, f.projectID, link.TokenHash, time.Now().UnixMilli())
	require.NoError(t, err)
	assert.Nil(t, open)

	resent := f.create(ctx, t, f.setup("ann@acme.com", "ann.other@example.com", f.other))
	require.False(t, resent.Created)
	assert.Equal(t, "ann.home@example.com", resent.PreviousDeliveryEmail)
	assert.Equal(t, int64(2), resent.User.SetupEpoch)
	assert.Equal(t, int64(2), resent.Invitation.SetupEpoch)
	assert.Equal(t, service.InvitationStatusRevoked, f.invitation(ctx, t, link).Status)

	_, err = f.complete(ctx, link)
	require.ErrorIs(t, err, service.ErrManagedSetupStale)

	done, err := f.complete(ctx, resent.Invitation)
	require.NoError(t, err)
	assert.True(t, done.FirstSetUp)
	assert.Equal(t, service.StatusActive, done.User.Status)
	assert.True(t, done.User.EmailVerified)
	assert.Equal(t, "hash-of-chosen-password", done.User.PasswordHash)
	assert.NotZero(t, done.User.SetUpAtMs)
	assert.Equal(t, service.MembershipStatusActive, done.Membership.Status)
	assert.Equal(t, service.RoleMember, done.Membership.Role)
	assert.Equal(t, service.MembershipSourceInvited, done.Membership.Source)
	assert.Equal(t, service.InvitationStatusAccepted, done.Invitation.Status)

	_, err = f.complete(ctx, resent.Invitation)
	require.ErrorIs(t, err, service.ErrInvitationUsed)
	_, err = f.is.CreateManagedSetup(ctx, f.setup("ann@acme.com", "ann.home@example.com", f.other))
	require.ErrorIs(t, err, service.ErrManagedByThisTenant)
}

// TestManagedSetup_CreateRefusals: every holder outside the tenant reads the
// same, an unverified domain and a caller who may not invite are refused,
// and nothing is written by a refusal.
func TestManagedSetup_CreateRefusals(t *testing.T) {
	ctx, f := newManagedFixture(t)

	_, err := f.is.CreateManagedSetup(ctx, f.setup("u1@acme.com", "x@example.com", f.other))
	require.ErrorIs(t, err, service.ErrManagedAddressUnavailable, "a personal account holds it")

	require.NoError(t, f.accounts.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: f.user, Email: "spare@acme.com", VerifiedAt: time.Now().UnixMilli()}, 5))
	_, err = f.is.CreateManagedSetup(ctx, f.setup("spare@acme.com", "x@example.com", f.other))
	require.ErrorIs(t, err, service.ErrManagedAddressUnavailable, "a recovery email holds it")

	now := time.Now()
	_, err = f.accounts.CreateUser(ctx, &service.User{Email: "elsewhere@acme.com", Status: service.StatusInvited, ManagedByTenantID: "another-tenant", SetupEpoch: 1, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	_, err = f.is.CreateManagedSetup(ctx, f.setup("elsewhere@acme.com", "x@example.com", f.other))
	require.ErrorIs(t, err, service.ErrManagedAddressUnavailable, "another tenant manages it")

	s := f.setup("bob@other.example.com", "x@example.com", f.other)
	s.Domain = "other.example.com"
	_, err = f.is.CreateManagedSetup(ctx, s)
	require.ErrorIs(t, err, service.ErrManagedDomainUnverified)

	s = f.setup("bob@acme.com", "x@example.com", f.other)
	s.Domain = "other.example.com"
	_, err = f.is.CreateManagedSetup(ctx, s)
	require.ErrorIs(t, err, service.ErrInvalidArgument, "the address must be on the domain")

	_, err = f.is.CreateManagedSetup(ctx, f.setup("bob@acme.com", "x@example.com", f.user))
	require.ErrorIs(t, err, service.ErrPermissionDenied, "a non-member may not invite")

	f.grant(ctx, t, f.user, service.RoleAdmin)
	s = f.setup("bob@acme.com", "x@example.com", f.user)
	s.Role = service.RoleOwner
	_, err = f.is.CreateManagedSetup(ctx, s)
	require.ErrorIs(t, err, service.ErrPermissionDenied, "only an owner issues an owner's link")

	s = f.setup("bob@acme.com", "x@example.com", f.other)
	s.Limits.MaxPerTenant = 0
	_, err = f.is.CreateManagedSetup(ctx, s)
	require.ErrorIs(t, err, service.ErrInvalidArgument)

	s = f.setup("bob@acme.com", "x@example.com", f.other)
	s.Limits.ResendCooldownStartMs = time.Now().Add(-time.Minute).UnixMilli()
	f.create(ctx, t, s)
	s.TokenHash = managedToken()
	_, err = f.is.CreateManagedSetup(ctx, s)
	require.ErrorIs(t, err, service.ErrInvitationResendTooSoon, "set-up links share the invitation limits")

	bob, err := f.accounts.FindUserByEmail(ctx, "bob@acme.com")
	require.NoError(t, err)
	assert.Equal(t, int64(1), bob.SetupEpoch, "a refused resend writes nothing")
	for _, address := range []string{"u1@acme.com", "spare@acme.com", "bob@other.example.com"} {
		u, err := f.accounts.FindUserByEmail(ctx, address)
		require.NoError(t, err)
		if u != nil {
			assert.Empty(t, u.ManagedByTenantID, address)
		}
	}
}

// TestManagedSetup_ResendOfOwnerLinkNeedsOwner: an admin may not replace
// an owner's pending link.
func TestManagedSetup_ResendOfOwnerLinkNeedsOwner(t *testing.T) {
	ctx, f := newManagedFixture(t)
	s := f.setup("ann@acme.com", "x@example.com", f.other)
	s.Role = service.RoleOwner
	f.create(ctx, t, s)
	f.grant(ctx, t, f.user, service.RoleAdmin)
	_, err := f.is.CreateManagedSetup(ctx, f.setup("ann@acme.com", "x@example.com", f.user))
	require.ErrorIs(t, err, service.ErrPermissionDenied)
}

// TestManagedSetup_CompleteRefusals: an expired link, a domain the tenant
// no longer verifies and an unknown or ordinary invitation are refused, and
// a suspended membership stays suspended through a set-up.
func TestManagedSetup_CompleteRefusals(t *testing.T) {
	ctx, f := newManagedFixture(t)

	s := f.setup("ann@acme.com", "x@example.com", f.other)
	s.ExpiresAtMs = time.Now().Add(-time.Minute).UnixMilli()
	expired := f.create(ctx, t, s)
	_, err := f.complete(ctx, expired.Invitation)
	require.ErrorIs(t, err, service.ErrInvitationExpired)

	_, err = f.complete(ctx, &service.TenantInvitation{ID: "no-such-link", TokenHash: managedToken()})
	require.ErrorIs(t, err, service.ErrNotFound)
	ordinary := &service.TenantInvitation{ProjectID: f.projectID, TenantID: f.tenantID, TokenHash: managedToken(), Email: "guest@example.com", InvitedBy: f.other, ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}
	_, err = f.is.CreateInvitation(ctx, ordinary, generousLimits())
	require.NoError(t, err)
	_, err = f.complete(ctx, ordinary)
	require.ErrorIs(t, err, service.ErrNotFound, "an ordinary invitation sets up nothing")

	pending := f.create(ctx, t, f.setup("ann@acme.com", "x@example.com", f.other))
	// Nothing in the store un-verifies a domain today; the write stands for
	// the later change that will.
	_, err = f.accounts.pool.Exec(ctx, `UPDATE domains SET status = 'pending' WHERE project_id = $1 AND id = $2`, f.projectID, f.domainID)
	require.NoError(t, err)
	_, err = f.complete(ctx, pending.Invitation)
	require.ErrorIs(t, err, service.ErrManagedDomainUnverified)
	assert.Equal(t, service.StatusInvited, f.readUser(ctx, t, pending.User.ID).Status)
}

// TestManagedSetup_SuspendedMembershipStaysSuspended: a set-up after a reset
// of a suspended account sets its password but leaves the membership
// suspended.
func TestManagedSetup_SuspendedMembershipStaysSuspended(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleMember)
	_, err := f.ms.SuspendManaged(ctx, f.projectID, f.tenantID, ann, f.other)
	require.NoError(t, err)
	reset, err := f.ms.ResetManaged(ctx, f.reset(ann, "ann.home@example.com", f.other))
	require.NoError(t, err)

	done, err := f.complete(ctx, reset.Invitation)
	require.NoError(t, err)
	assert.False(t, done.FirstSetUp)
	assert.Equal(t, service.StatusActive, done.User.Status)
	assert.Equal(t, service.MembershipStatusSuspended, done.Membership.Status)
	assert.Equal(t, service.MembershipStatusSuspended, f.membership(ctx, t, ann).Status)
}

// TestRevokeManagedSetup: revoking a never-set-up account's link deletes
// the account and all its links, at any status of the link; an accepted
// link is refused and an ordinary invitation is not one.
func TestRevokeManagedSetup(t *testing.T) {
	ctx, f := newManagedFixture(t)

	first := f.create(ctx, t, f.setup("ann@acme.com", "x@example.com", f.other))
	second := f.create(ctx, t, f.setup("ann@acme.com", "y@example.com", f.other))
	revoked, err := f.is.RevokeManagedSetup(ctx, f.projectID, f.tenantID, first.Invitation.ID, f.other)
	require.NoError(t, err)
	assert.False(t, revoked.Changed, "the first link was already replaced")
	require.NotNil(t, revoked.DeletedUser)
	assert.Equal(t, first.User.ID, revoked.DeletedUser.ID)
	assert.Nil(t, f.readUser(ctx, t, first.User.ID))
	assert.Equal(t, service.InvitationStatusRevoked, f.invitation(ctx, t, second.Invitation).Status)

	pending := f.create(ctx, t, f.setup("bob@acme.com", "x@example.com", f.other))
	revoked, err = f.is.RevokeManagedSetup(ctx, f.projectID, f.tenantID, pending.Invitation.ID, f.other)
	require.NoError(t, err)
	assert.True(t, revoked.Changed)
	assert.Equal(t, service.InvitationStatusRevoked, revoked.Invitation.Status)
	assert.NotNil(t, revoked.DeletedUser)

	setUp := f.create(ctx, t, f.setup("cy@acme.com", "x@example.com", f.other))
	_, err = f.complete(ctx, setUp.Invitation)
	require.NoError(t, err)
	_, err = f.is.RevokeManagedSetup(ctx, f.projectID, f.tenantID, setUp.Invitation.ID, f.other)
	require.ErrorIs(t, err, service.ErrInvitationUsed)
	assert.NotNil(t, f.readUser(ctx, t, setUp.User.ID))

	_, err = f.is.RevokeManagedSetup(ctx, f.projectID, "another-tenant", setUp.Invitation.ID, f.other)
	require.ErrorIs(t, err, service.ErrNotFound)
	ordinary := &service.TenantInvitation{ProjectID: f.projectID, TenantID: f.tenantID, TokenHash: managedToken(), Email: "guest@example.com", InvitedBy: f.other, ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}
	_, err = f.is.CreateInvitation(ctx, ordinary, generousLimits())
	require.NoError(t, err)
	_, err = f.is.RevokeManagedSetup(ctx, f.projectID, f.tenantID, ordinary.ID, f.other)
	require.ErrorIs(t, err, service.ErrNotFound)
}

// TestManagedAddressHolders reads who holds each address as the tenant
// sees it, a recovery email included.
func TestManagedAddressHolders(t *testing.T) {
	ctx, f := newManagedFixture(t)
	f.create(ctx, t, f.setup("ann@acme.com", "x@example.com", f.other))
	require.NoError(t, f.accounts.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: f.user, Email: "spare@acme.com", VerifiedAt: time.Now().UnixMilli()}, 5))

	now := time.Now()
	_, err := f.accounts.CreateUser(ctx, &service.User{Email: "held@other.example.com", Status: "active", CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)

	got, err := f.is.ManagedAddressHolders(ctx, f.projectID, f.tenantID, []string{"ann@acme.com", "u1@acme.com", "spare@acme.com", "free@acme.com", "held@other.example.com", "free@other.example.com"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"ann@acme.com":           service.ManagedAddressManagedByThis,
		"u1@acme.com":            service.ManagedAddressHeldOutsideTheTenant,
		"spare@acme.com":         service.ManagedAddressHeldOutsideTheTenant,
		"free@acme.com":          service.ManagedAddressFree,
		"held@other.example.com": service.ManagedAddressDomainUnverified,
		"free@other.example.com": service.ManagedAddressDomainUnverified,
	}, got, "an address off the tenant's verified domains is never looked up")

	got, err = f.is.ManagedAddressHolders(ctx, f.projectID, "another-tenant", []string{"ann@acme.com"})
	require.NoError(t, err)
	assert.Equal(t, service.ManagedAddressDomainUnverified, got["ann@acme.com"], "another tenant learns nothing about acme.com")
}

// TestSuspendManaged: a suspension ends the account's sessions, refresh
// tokens and agents in the same write, and is refused for a caller who is
// not an owner or admin and for a personal account.
func TestSuspendManaged(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleMember)
	sid := f.signIn(ctx, t, ann)
	agent := f.agentOf(ctx, t, ann)
	agentSID := f.signIn(ctx, t, agent)

	_, err := f.ms.SuspendManaged(ctx, f.projectID, f.tenantID, ann, f.user)
	require.ErrorIs(t, err, service.ErrPermissionDenied)
	f.grant(ctx, t, f.user, service.RoleMember)
	_, err = f.ms.SuspendManaged(ctx, f.projectID, f.tenantID, f.user, f.other)
	require.ErrorIs(t, err, service.ErrNotFound, "a personal account is not managed")

	change, err := f.ms.SuspendManaged(ctx, f.projectID, f.tenantID, ann, f.other)
	require.NoError(t, err)
	assert.True(t, change.Changed)
	assert.Equal(t, service.MembershipStatusSuspended, change.Membership.Status)
	assert.ElementsMatch(t, []string{sid, agentSID}, change.RevokedSessionIDs)
	assert.Equal(t, []string{agent}, change.DeactivatedAgentIDs)
	assert.False(t, f.sessionLive(ctx, t, sid))
	assert.False(t, f.sessionLive(ctx, t, agentSID))
	assert.Zero(t, f.refreshTokens(ctx, t, ann))
	assert.Zero(t, f.refreshTokens(ctx, t, agent))
	assert.Equal(t, service.StatusDeactivated, f.readUser(ctx, t, agent).Status)
	assert.Equal(t, service.StatusActive, f.readUser(ctx, t, ann).Status)

	again, err := f.ms.SuspendManaged(ctx, f.projectID, f.tenantID, ann, f.other)
	require.NoError(t, err)
	assert.False(t, again.Changed)
	assert.Empty(t, again.RevokedSessionIDs)
}

// TestSuspendManaged_KeepsAnOwner: the tenant's last active owner is not
// suspended or removed.
func TestSuspendManaged_KeepsAnOwner(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleOwner)
	_, err := f.ms.RemoveMembership(ctx, f.projectID, f.tenantID, f.other)
	require.NoError(t, err)
	f.grant(ctx, t, f.user, service.RoleAdmin)
	_, err = f.ms.SuspendManaged(ctx, f.projectID, f.tenantID, ann, f.user)
	require.ErrorIs(t, err, service.ErrLastOwner)
	_, err = f.ms.RemoveManaged(ctx, f.projectID, f.tenantID, ann, f.user)
	require.ErrorIs(t, err, service.ErrLastOwner)
}

// TestRemoveManaged: a removal deactivates the account, keeps its id and
// address, records the removal and ends its sessions, agents and links.
func TestRemoveManaged(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleMember)
	sid := f.signIn(ctx, t, ann)
	agent := f.agentOf(ctx, t, ann)

	change, err := f.ms.RemoveManaged(ctx, f.projectID, f.tenantID, ann, f.other)
	require.NoError(t, err)
	assert.True(t, change.Changed)
	assert.Equal(t, ann, change.Membership.UserID)
	assert.Equal(t, []string{sid}, change.RevokedSessionIDs)
	assert.Equal(t, []string{agent}, change.DeactivatedAgentIDs)
	assert.Nil(t, f.membership(ctx, t, ann))
	removed, err := f.ms.IsRemoved(ctx, f.projectID, f.tenantID, ann)
	require.NoError(t, err)
	assert.True(t, removed)
	account := f.readUser(ctx, t, ann)
	assert.Equal(t, service.StatusDeactivated, account.Status)
	assert.Equal(t, "ann@acme.com", account.Email)
	assert.Equal(t, f.tenantID, account.ManagedByTenantID)

	_, err = f.ms.RemoveManaged(ctx, f.projectID, f.tenantID, ann, f.other)
	require.ErrorIs(t, err, service.ErrNotFound)
	_, err = f.ms.ResetManaged(ctx, f.reset(ann, "x@example.com", f.other))
	require.ErrorIs(t, err, service.ErrNotFound, "a removed account is not reset")
	_, err = f.is.CreateManagedSetup(ctx, f.setup("ann@acme.com", "x@example.com", f.other))
	require.ErrorIs(t, err, service.ErrManagedByThisTenant, "a removed account keeps its address")
}

func (f *managedFixture) reset(userID, delivery, by string) service.ManagedReset {
	return service.ManagedReset{
		ProjectID: f.projectID, TenantID: f.tenantID, UserID: userID, By: by, DeliveryEmail: delivery,
		TokenHash: managedToken(), ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(), Limits: generousLimits(),
	}
}

// TestResetManaged: a reset clears every credential and link, ends every
// session, keeps the membership, and issues a new link with the member's
// role that sets the account up again.
func TestResetManaged(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleAdmin)
	sid := f.signIn(ctx, t, ann)
	agent := f.agentOf(ctx, t, ann)
	now := time.Now().UnixMilli()
	require.NoError(t, f.accounts.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: ann, Email: "ann.home@example.com", VerifiedAt: now}, 5))
	_, err := f.accounts.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{CredentialID: "cred-ann", UserID: ann, PublicKey: "pk", CreatedAt: now})
	require.NoError(t, err)
	_, err = f.accounts.CreateTotpCredential(ctx, &service.TotpCredRecord{UserID: ann, SecretEncrypted: "secret", Verified: true, CreatedAt: now})
	require.NoError(t, err)
	_, err = f.accounts.CreateRecoveryCode(ctx, &service.RecoveryCodeRecord{UserID: ann, CodeHash: "code", CreatedAt: now})
	require.NoError(t, err)
	require.NoError(t, f.accounts.CreatePasswordResetToken(ctx, &service.PasswordResetToken{TokenHash: "reset-ann", UserID: ann, Email: "ann@acme.com", ExpiresAt: now + 60_000, CreatedAt: now}))
	_, err = f.accounts.ClaimPhoneNumber(ctx, ann, "+15550100", now, 0)
	require.NoError(t, err)
	require.NoError(t, f.accounts.UpdateUser(ctx, ann, map[string]any{"totp_required": true, "phone_number": "+15550100", "phone_verified": true, "failed_login_count": int64(3), "locked_until": now + 60_000}))

	f.grant(ctx, t, f.user, service.RoleAdmin)
	_, err = f.ms.ResetManaged(ctx, f.reset(ann, "x@example.com", ann))
	require.ErrorIs(t, err, service.ErrInvalidArgument, "nobody resets their own account")

	done, err := f.ms.ResetManaged(ctx, f.reset(ann, "ann.new@example.com", f.user))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"ann@acme.com", "ann.home@example.com"}, done.NoticeEmails)
	assert.Equal(t, []string{sid}, done.RevokedSessionIDs)
	assert.Equal(t, []string{agent}, done.DeactivatedAgentIDs)

	account := f.readUser(ctx, t, ann)
	assert.Equal(t, service.StatusInvited, account.Status)
	assert.Empty(t, account.PasswordHash)
	assert.False(t, account.TotpRequired)
	assert.Empty(t, account.PhoneNumber)
	assert.False(t, account.PhoneVerified)
	assert.Zero(t, account.FailedLoginCount)
	assert.Zero(t, account.LockedUntil)
	assert.Equal(t, int64(2), account.SetupEpoch)
	assert.NotZero(t, account.SetUpAtMs, "a reset keeps the first set-up time")
	for _, table := range []string{"passkeys", "user_recovery_emails", "totp_secrets", "recovery_codes", "phone_number_claims", "refresh_tokens"} {
		var n int
		require.NoError(t, f.accounts.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE project_id = $1 AND user_id = $2`, f.projectID, ann).Scan(&n))
		assert.Zero(t, n, table)
	}
	var consumed int64
	require.NoError(t, f.accounts.pool.QueryRow(ctx, `SELECT consumed_at_ms FROM password_reset_tokens WHERE project_id = $1 AND token_hash = 'reset-ann'`, f.projectID).Scan(&consumed))
	assert.NotZero(t, consumed)
	assert.False(t, f.sessionLive(ctx, t, sid))

	m := f.membership(ctx, t, ann)
	assert.Equal(t, service.MembershipStatusActive, m.Status)
	assert.Equal(t, service.RoleAdmin, m.Role)
	assert.Equal(t, service.RoleAdmin, done.Invitation.Role)
	assert.Equal(t, "ann.new@example.com", done.Invitation.DeliveryEmail)
	assert.Equal(t, int64(2), done.Invitation.SetupEpoch)
	assert.Equal(t, f.user, done.Invitation.InvitedBy)

	set, err := f.complete(ctx, done.Invitation)
	require.NoError(t, err)
	assert.False(t, set.FirstSetUp)
	assert.Equal(t, service.StatusActive, set.User.Status)
	assert.Equal(t, service.RoleAdmin, set.Membership.Role)
}

// TestResetManaged_Refusals: an admin does not reset an owner, a caller who
// is not an owner or admin resets nobody, and the per-delivery-address cap
// holds.
func TestResetManaged_Refusals(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleOwner)

	_, err := f.ms.ResetManaged(ctx, f.reset(ann, "x@example.com", f.user))
	require.ErrorIs(t, err, service.ErrPermissionDenied)
	f.grant(ctx, t, f.user, service.RoleAdmin)
	_, err = f.ms.ResetManaged(ctx, f.reset(ann, "x@example.com", f.user))
	require.ErrorIs(t, err, service.ErrPermissionDenied, "only an owner resets an owner")

	capped := f.reset(ann, "cap@example.com", f.other)
	capped.MaxPerDeliveryEmail = 1
	_, err = f.ms.ResetManaged(ctx, capped)
	require.NoError(t, err)
	capped.TokenHash = managedToken()
	_, err = f.ms.ResetManaged(ctx, capped)
	require.ErrorIs(t, err, service.ErrManagedResetLimited)
	capped.DeliveryEmail = "CAP@example.com"
	capped.TokenHash = managedToken()
	_, err = f.ms.ResetManaged(ctx, capped)
	require.ErrorIs(t, err, service.ErrManagedResetLimited, "the cap counts the address under its folded form")
}

// raceRounds is how often each race runs, so both orders occur.
const raceRounds = 8

// TestManagedRace_SuspendAndSetUp: a suspension racing a set-up after a
// reset always leaves the membership suspended, whichever lands first, and
// never leaves a live session.
func TestManagedRace_SuspendAndSetUp(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleMember)
	for range raceRounds {
		_, _, err := f.ms.RestoreMembership(ctx, f.projectID, f.tenantID, ann, service.RestoredByOperator())
		require.NoError(t, err)
		reset, err := f.ms.ResetManaged(ctx, f.reset(ann, "x@example.com", f.other))
		require.NoError(t, err)
		errSetUp, errSuspend := runTogether(
			func() error { _, err := f.complete(ctx, reset.Invitation); return err },
			func() error { _, err := f.ms.SuspendManaged(ctx, f.projectID, f.tenantID, ann, f.other); return err },
		)
		require.NoError(t, errSetUp)
		require.NoError(t, errSuspend)
		assert.Equal(t, service.MembershipStatusSuspended, f.membership(ctx, t, ann).Status)
		assert.Equal(t, service.StatusActive, f.readUser(ctx, t, ann).Status)
	}
}

// TestManagedRace_ResetAndSetUp: a reset racing a set-up from the link
// before it ends with the account invited and the reset's link the one
// pending; the set-up either landed first or is refused as stale.
func TestManagedRace_ResetAndSetUp(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleMember)
	for range raceRounds {
		before, err := f.ms.ResetManaged(ctx, f.reset(ann, "x@example.com", f.other))
		require.NoError(t, err)
		var after *service.ManagedResetDone
		errSetUp, errReset := runTogether(
			func() error { _, err := f.complete(ctx, before.Invitation); return err },
			func() error {
				var err error
				after, err = f.ms.ResetManaged(ctx, f.reset(ann, "y@example.com", f.other))
				return err
			},
		)
		require.NoError(t, errReset)
		if errSetUp != nil {
			require.ErrorIs(t, errSetUp, service.ErrManagedSetupStale)
			assert.Equal(t, service.InvitationStatusRevoked, f.invitation(ctx, t, before.Invitation).Status)
		} else {
			assert.Equal(t, service.InvitationStatusAccepted, f.invitation(ctx, t, before.Invitation).Status)
		}
		account := f.readUser(ctx, t, ann)
		assert.Equal(t, service.StatusInvited, account.Status)
		assert.Empty(t, account.PasswordHash, "a set-up never outlives the reset after it")
		assert.Equal(t, after.User.SetupEpoch, account.SetupEpoch)
		assert.Equal(t, service.InvitationStatusPending, f.invitation(ctx, t, after.Invitation).Status)
		_, err = f.complete(ctx, after.Invitation)
		require.NoError(t, err)
	}
}

// TestManagedRace_RevokeAndSetUp: a revoke racing the first set-up either
// deletes the account, and the set-up is refused, or comes second and is
// refused itself, leaving the account set up.
func TestManagedRace_RevokeAndSetUp(t *testing.T) {
	ctx, f := newManagedFixture(t)
	for i := range raceRounds {
		issued := f.create(ctx, t, f.setup(fmt.Sprintf("race%d@acme.com", i), "x@example.com", f.other))
		errSetUp, errRevoke := runTogether(
			func() error { _, err := f.complete(ctx, issued.Invitation); return err },
			func() error {
				_, err := f.is.RevokeManagedSetup(ctx, f.projectID, f.tenantID, issued.Invitation.ID, f.other)
				return err
			},
		)
		account := f.readUser(ctx, t, issued.User.ID)
		switch {
		case errSetUp == nil:
			require.ErrorIs(t, errRevoke, service.ErrInvitationUsed)
			require.NotNil(t, account)
			assert.Equal(t, service.StatusActive, account.Status)
			assert.Equal(t, service.MembershipStatusActive, f.membership(ctx, t, issued.User.ID).Status)
		case errRevoke == nil:
			require.True(t, errors.Is(errSetUp, service.ErrManagedSetupStale) || errors.Is(errSetUp, service.ErrNotFound), "set-up after revoke: %v", errSetUp)
			assert.Nil(t, account)
			assert.Nil(t, f.membership(ctx, t, issued.User.ID))
		default:
			t.Fatalf("one of them must win: set-up %v, revoke %v", errSetUp, errRevoke)
		}
	}
}

// The admin surfaces read users through the graph layer: a managed
// account's tenant, set-up time and epoch travel with it, and a personal
// account reads back unmanaged.
func TestPostgres_DBUserNodeCarriesManagedAccount(t *testing.T) {
	ctx, f := newManagedFixture(t)
	issued := f.create(ctx, t, f.setup("ann@acme.com", "x@example.com", f.other))
	done, err := f.complete(ctx, issued.Invitation)
	require.NoError(t, err)

	node, err := f.accounts.GetNode(ctx, f.projectID, "actor", dbTypeUser, issued.User.ID)
	require.NoError(t, err)
	assert.Equal(t, f.tenantID, node.Payload[dbUfManagedByTenantID])
	assert.Equal(t, done.User.SetUpAtMs, node.Payload[dbUfSetUpAt])
	assert.Equal(t, int64(1), node.Payload[dbUfSetupEpoch])

	node, err = f.accounts.GetNode(ctx, f.projectID, "actor", dbTypeUser, f.user)
	require.NoError(t, err)
	assert.Equal(t, "", node.Payload[dbUfManagedByTenantID])
	assert.Equal(t, int64(0), node.Payload[dbUfSetUpAt])
	assert.Equal(t, int64(0), node.Payload[dbUfSetupEpoch])
}

// An ordinary invitation never replaces a managed account's pending set-up
// link in the tenant.
func TestCreateInvitation_KeepsAPendingSetUpLink(t *testing.T) {
	ctx, f := newManagedFixture(t)
	issued := f.create(ctx, t, f.setup("ann@acme.com", "x@example.com", f.other))
	_, err := f.is.CreateInvitation(ctx, &service.TenantInvitation{
		ProjectID: f.projectID, TenantID: f.tenantID, TokenHash: managedToken(), Email: "Ann@acme.com",
		InvitedBy: f.other, ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(),
	}, generousLimits())
	require.ErrorIs(t, err, service.ErrManagedByThisTenant)
	assert.Equal(t, service.InvitationStatusPending, f.invitation(ctx, t, issued.Invitation).Status)
}

// A set-up after a reset keeps the role the member holds now: a demotion
// made after the reset is not undone by the link the reset issued.
func TestManagedSetup_AfterResetKeepsTheCurrentRole(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleAdmin)
	reset, err := f.ms.ResetManaged(ctx, f.reset(ann, "x@example.com", f.other))
	require.NoError(t, err)
	require.Equal(t, service.RoleAdmin, reset.Invitation.Role)
	_, _, err = f.ms.SetMemberRole(ctx, service.MemberRoleChange{ProjectID: f.projectID, TenantID: f.tenantID, UserID: ann, Role: service.RoleMember, By: f.other})
	require.NoError(t, err)

	done, err := f.complete(ctx, reset.Invitation)
	require.NoError(t, err)
	assert.Equal(t, service.RoleMember, done.Membership.Role)
	assert.Equal(t, service.RoleMember, f.membership(ctx, t, ann).Role)
}

// A set-up is refused once the tenant can no longer take members: it is
// suspended, or no active owner or admin is left.
func TestManagedSetup_CompleteNeedsAGovernedTenant(t *testing.T) {
	ctx, f := newManagedFixture(t)
	suspended := f.create(ctx, t, f.setup("ann@acme.com", "x@example.com", f.other))
	_, err := f.accounts.pool.Exec(ctx, `UPDATE tenants SET status = $3 WHERE project_id = $1 AND id = $2`, f.projectID, f.tenantID, service.TenantStatusSuspended)
	require.NoError(t, err)
	_, err = f.complete(ctx, suspended.Invitation)
	require.ErrorIs(t, err, service.ErrPermissionDenied)
	_, err = f.accounts.pool.Exec(ctx, `UPDATE tenants SET status = $3 WHERE project_id = $1 AND id = $2`, f.projectID, f.tenantID, service.TenantStatusClaimed)
	require.NoError(t, err)

	_, err = f.accounts.pool.Exec(ctx, `UPDATE tenant_memberships SET status = 'suspended' WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`, f.projectID, f.tenantID, f.other)
	require.NoError(t, err)
	_, err = f.complete(ctx, suspended.Invitation)
	require.ErrorIs(t, err, service.ErrPermissionDenied, "no active owner or admin is left")
	assert.Equal(t, service.StatusInvited, f.readUser(ctx, t, suspended.User.ID).Status)
}

// Only an active owner or admin revokes a set-up link, and only a known role
// is issued.
func TestManagedSetup_RevokeAndRoleRefusals(t *testing.T) {
	ctx, f := newManagedFixture(t)
	issued := f.create(ctx, t, f.setup("ann@acme.com", "x@example.com", f.other))
	_, err := f.is.RevokeManagedSetup(ctx, f.projectID, f.tenantID, issued.Invitation.ID, f.user)
	require.ErrorIs(t, err, service.ErrPermissionDenied)
	assert.NotNil(t, f.readUser(ctx, t, issued.User.ID))

	s := f.setup("bob@acme.com", "x@example.com", f.other)
	s.Role = "superuser"
	_, err = f.is.CreateManagedSetup(ctx, s)
	require.ErrorIs(t, err, service.ErrInvalidArgument)
}

// A set-up link stops working once its issuer may no longer issue it, as an
// ordinary invitation does: the issuer is removed, or, for an owner's link,
// is no longer an owner.
func TestManagedSetup_CompleteNeedsTheIssuer(t *testing.T) {
	ctx, f := newManagedFixture(t)
	f.grant(ctx, t, f.user, service.RoleAdmin)
	byAdmin := f.create(ctx, t, f.setup("ann@acme.com", "x@example.com", f.user))
	_, err := f.ms.RemoveMembership(ctx, f.projectID, f.tenantID, f.user)
	require.NoError(t, err)
	_, err = f.complete(ctx, byAdmin.Invitation)
	require.ErrorIs(t, err, service.ErrPermissionDenied, "the issuer was removed")
	assert.Equal(t, service.StatusInvited, f.readUser(ctx, t, byAdmin.User.ID).Status)

	owner := f.accountWithID(ctx, t, "", "second.owner@acme.com")
	f.grant(ctx, t, owner, service.RoleOwner)
	s := f.setup("bob@acme.com", "x@example.com", owner)
	s.Role = service.RoleOwner
	ownerLink := f.create(ctx, t, s)
	_, _, err = f.ms.TransferOwnership(ctx, f.projectID, f.tenantID, owner, f.other)
	require.NoError(t, err)
	_, err = f.complete(ctx, ownerLink.Invitation)
	require.ErrorIs(t, err, service.ErrPermissionDenied, "the issuer of an owner's link is no longer an owner")

	byOther := f.create(ctx, t, f.setup("cy@acme.com", "x@example.com", f.other))
	_, err = f.complete(ctx, &service.TenantInvitation{ID: byOther.Invitation.ID, TokenHash: "not-the-links-token"})
	require.ErrorIs(t, err, service.ErrNotFound, "the token must be the link's")
	_, err = f.complete(ctx, byOther.Invitation)
	require.NoError(t, err)
}

// A member removed from the tenant is not brought back by a set-up link: the
// removal revokes the account's pending links, and a link that escaped it is
// refused.
func TestManagedSetup_RemovedMemberIsNotBroughtBack(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleMember)
	reset, err := f.ms.ResetManaged(ctx, f.reset(ann, "x@example.com", f.other))
	require.NoError(t, err)
	_, err = f.ms.RemoveMembership(ctx, f.projectID, f.tenantID, ann)
	require.NoError(t, err)
	assert.Equal(t, service.InvitationStatusRevoked, f.invitation(ctx, t, reset.Invitation).Status)
	_, err = f.complete(ctx, reset.Invitation)
	require.ErrorIs(t, err, service.ErrManagedSetupStale)

	_, err = f.accounts.pool.Exec(ctx, `UPDATE tenant_invitations SET status = 'pending' WHERE project_id = $1 AND id = $2`, f.projectID, reset.Invitation.ID)
	require.NoError(t, err)
	_, err = f.complete(ctx, reset.Invitation)
	require.ErrorIs(t, err, service.ErrRemovedFromTenant)
	assert.Nil(t, f.membership(ctx, t, ann))
}

// A refusal over who holds the address is said only once the domain and the
// inviter have passed, so nobody can use it to probe addresses.
func TestManagedSetup_HolderRefusalComesLast(t *testing.T) {
	ctx, f := newManagedFixture(t)
	_, err := f.is.CreateManagedSetup(ctx, f.setup("u1@acme.com", "x@example.com", f.user))
	require.ErrorIs(t, err, service.ErrPermissionDenied, "a non-governor learns nothing about u1@acme.com")
	_, err = f.accounts.pool.Exec(ctx, `UPDATE domains SET status = 'pending' WHERE project_id = $1 AND id = $2`, f.projectID, f.domainID)
	require.NoError(t, err)
	_, err = f.is.CreateManagedSetup(ctx, f.setup("u1@acme.com", "x@example.com", f.other))
	require.ErrorIs(t, err, service.ErrManagedDomainUnverified, "an unverified domain says nothing of its holders")
}

// A managed account holds a membership in its own tenant only: every write
// that would give it one elsewhere is refused, and a reset refuses an
// account that holds one.
func TestManagedAccount_NoMembershipElsewhere(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleMember)
	other, err := f.tenants.CreateTenant(ctx, &service.Tenant{ProjectID: f.projectID, Status: service.TenantStatusClaimed})
	require.NoError(t, err)

	_, _, err = f.ms.GrantMembership(ctx, &service.TenantMembership{ProjectID: f.projectID, TenantID: other, UserID: ann, Source: service.MembershipSourceInvited, Role: service.RoleMember})
	require.ErrorIs(t, err, service.ErrManagedElsewhere, "an invitation accepted elsewhere")
	_, _, err = f.ms.JoinByDomain(ctx, f.projectID, other, ann, f.domainID)
	require.ErrorIs(t, err, service.ErrManagedElsewhere)
	_, _, err = f.ms.AddMember(ctx, f.projectID, other, ann)
	require.ErrorIs(t, err, service.ErrManagedElsewhere)
	_, err = f.ms.UpsertMembership(ctx, &service.TenantMembership{ProjectID: f.projectID, TenantID: other, UserID: ann})
	require.ErrorIs(t, err, service.ErrManagedElsewhere)
	_, _, err = f.tenants.CreateOwnedTenant(ctx, service.OwnedTenantRequest{ProjectID: f.projectID, Name: "Side project", OwnerID: ann, MaxPerWindow: 10})
	require.ErrorIs(t, err, service.ErrManagedElsewhere)
	autoform := &AutoFormStore{pool: f.ms.pool}
	joined, err := autoform.EnsureTenantForDomain(ctx, f.projectID, "other.example.com", ann)
	require.NoError(t, err)
	assert.Equal(t, f.tenantID, joined, "a managed account forms no tenant and joins only its own")
	var elsewhere int
	require.NoError(t, f.accounts.pool.QueryRow(ctx, `SELECT count(*) FROM tenant_memberships WHERE project_id = $1 AND user_id = $2 AND tenant_id <> $3`, f.projectID, ann, f.tenantID).Scan(&elsewhere))
	assert.Zero(t, elsewhere)
	var latent int
	require.NoError(t, f.accounts.pool.QueryRow(ctx, `SELECT count(*) FROM domains WHERE project_id = $1 AND lower(domain) = 'other.example.com'`, f.projectID).Scan(&latent))
	assert.Zero(t, latent, "the refused auto-formation created nothing")

	_, _, err = f.ms.GrantMembership(ctx, &service.TenantMembership{ProjectID: f.projectID, TenantID: other, UserID: f.user, Source: service.MembershipSourceInvited, Role: service.RoleMember})
	require.NoError(t, err, "a personal account is unaffected")

	_, err = f.accounts.pool.Exec(ctx, `INSERT INTO tenant_memberships (id, project_id, tenant_id, user_id, source, role, status, created_at_ms, updated_at_ms)
		VALUES ('stray', $1, $2, $3, 'added', 'member', 'active', 0, 0)`, f.projectID, other, ann)
	require.NoError(t, err)
	_, err = f.ms.ResetManaged(ctx, f.reset(ann, "x@example.com", f.other))
	require.ErrorIs(t, err, service.ErrManagedElsewhere)
	assert.Equal(t, service.StatusActive, f.readUser(ctx, t, ann).Status)
}

// Suspend, remove and reset also end the sign-ins already under way: approved
// QR hand-offs expire, unredeemed OAuth one-time codes are spent and pending
// sign-in challenges are deleted.
func TestManagedSignOut_EndsSignInsUnderWay(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleMember)
	now := time.Now()
	seed := func(t *testing.T, suffix string) {
		t.Helper()
		_, err := f.accounts.pool.Exec(ctx, `
			INSERT INTO qr_login_sessions (id, project_id, session_id, status, user_id, expires_at_ms, created_at_ms, updated_at_ms)
			VALUES ('qr-'||$3, $1, 'qs-'||$3, 'approved', $2, $4, 0, 0);
		`, f.projectID, ann, suffix, now.Add(time.Hour).UnixMilli())
		require.NoError(t, err)
		_, err = f.accounts.pool.Exec(ctx, `
			INSERT INTO oauth_one_time_codes (id, project_id, code_hash, user_id, expires_at_ms, created_at_ms)
			VALUES ('otc-'||$3, $1, 'code-'||$3, $2, $4, 0)`, f.projectID, ann, suffix, now.Add(time.Hour).UnixMilli())
		require.NoError(t, err)
		_, err = f.accounts.pool.Exec(ctx, `
			INSERT INTO login_challenges (id, project_id, challenge_id, user_id, expires_at_ms, created_at_ms)
			VALUES ('lc-'||$3, $1, 'ch-'||$3, $2, $4, 0)`, f.projectID, ann, suffix, now.Add(time.Hour).UnixMilli())
		require.NoError(t, err)
	}
	assertEnded := func(t *testing.T, suffix string) {
		t.Helper()
		var qrStatus string
		var consumed int64
		var challenges int
		require.NoError(t, f.accounts.pool.QueryRow(ctx, `SELECT status FROM qr_login_sessions WHERE project_id = $1 AND id = 'qr-'||$2`, f.projectID, suffix).Scan(&qrStatus))
		require.NoError(t, f.accounts.pool.QueryRow(ctx, `SELECT consumed_at_ms FROM oauth_one_time_codes WHERE project_id = $1 AND id = 'otc-'||$2`, f.projectID, suffix).Scan(&consumed))
		require.NoError(t, f.accounts.pool.QueryRow(ctx, `SELECT count(*) FROM login_challenges WHERE project_id = $1 AND id = 'lc-'||$2`, f.projectID, suffix).Scan(&challenges))
		assert.Equal(t, "expired", qrStatus, suffix)
		assert.NotZero(t, consumed, suffix)
		assert.Zero(t, challenges, suffix)
	}

	seed(t, "suspend")
	_, err := f.ms.SuspendManaged(ctx, f.projectID, f.tenantID, ann, f.other)
	require.NoError(t, err)
	assertEnded(t, "suspend")

	seed(t, "reset")
	_, err = f.ms.ResetManaged(ctx, f.reset(ann, "x@example.com", f.other))
	require.NoError(t, err)
	assertEnded(t, "reset")

	seed(t, "remove")
	_, err = f.ms.RemoveManaged(ctx, f.projectID, f.tenantID, ann, f.other)
	require.NoError(t, err)
	assertEnded(t, "remove")
}

// The per-delivery-address cap holds for new set-up links too.
func TestManagedSetup_CreateCapsTheDeliveryAddress(t *testing.T) {
	ctx, f := newManagedFixture(t)
	s := f.setup("ann@acme.com", "home@example.com", f.other)
	s.MaxPerDeliveryEmail = 1
	f.create(ctx, t, s)
	s = f.setup("bob@acme.com", "Home@example.com", f.other)
	s.MaxPerDeliveryEmail = 1
	_, err := f.is.CreateManagedSetup(ctx, s)
	require.ErrorIs(t, err, service.ErrManagedResetLimited)
	bob, err := f.accounts.FindUserByEmail(ctx, "bob@acme.com")
	require.NoError(t, err)
	assert.Nil(t, bob, "a refused create writes nothing")
}

// An ordinary revoke does not touch a set-up link, and a tenant that is not
// claimed issues none.
func TestManagedSetup_OrdinaryRevokeAndTenantStatus(t *testing.T) {
	ctx, f := newManagedFixture(t)
	issued := f.create(ctx, t, f.setup("ann@acme.com", "x@example.com", f.other))
	_, _, err := f.is.RevokeInvitation(ctx, f.projectID, f.tenantID, issued.Invitation.ID)
	require.ErrorIs(t, err, service.ErrNotFound)
	assert.Equal(t, service.InvitationStatusPending, f.invitation(ctx, t, issued.Invitation).Status)

	_, err = f.accounts.pool.Exec(ctx, `UPDATE tenants SET status = $3 WHERE project_id = $1 AND id = $2`, f.projectID, f.tenantID, service.TenantStatusSuspended)
	require.NoError(t, err)
	_, err = f.is.CreateManagedSetup(ctx, f.setup("bob@acme.com", "x@example.com", f.other))
	require.ErrorIs(t, err, service.ErrPermissionDenied)
}

// Auto-formation records a managed account's membership in the tenant that
// manages it even while that tenant is suspended, and never forms or joins
// another for it.
func TestManagedAutoForm_SuspendedManagingTenant(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleMember)
	_, err := f.accounts.pool.Exec(ctx, `UPDATE tenants SET status = $3 WHERE project_id = $1 AND id = $2`, f.projectID, f.tenantID, service.TenantStatusSuspended)
	require.NoError(t, err)
	var tenantsBefore int
	require.NoError(t, f.accounts.pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE project_id = $1`, f.projectID).Scan(&tenantsBefore))

	joined, err := (&AutoFormStore{pool: f.ms.pool}).EnsureTenantForDomain(ctx, f.projectID, "acme.com", ann)
	require.NoError(t, err)
	assert.Equal(t, f.tenantID, joined)
	var tenantsAfter int
	require.NoError(t, f.accounts.pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE project_id = $1`, f.projectID).Scan(&tenantsAfter))
	assert.Equal(t, tenantsBefore, tenantsAfter, "no tenant was formed")
	m := f.membership(ctx, t, ann)
	require.NotNil(t, m)
	assert.Equal(t, service.MembershipSourceInvited, m.Source, "the membership it holds keeps its source")
}

// An agent a managed account owns is held to its owner's tenant, while an
// agent a person owns is not.
func TestManagedAccount_AgentsFollowTheirOwnersTenant(t *testing.T) {
	ctx, f := newManagedFixture(t)
	ann := f.setUpAccount(ctx, t, service.RoleMember)
	annsAgent := f.agentOf(ctx, t, ann)
	personsAgent := f.agentOf(ctx, t, f.user)
	other, err := f.tenants.CreateTenant(ctx, &service.Tenant{ProjectID: f.projectID, Status: service.TenantStatusClaimed})
	require.NoError(t, err)

	_, _, err = f.ms.GrantMembership(ctx, &service.TenantMembership{ProjectID: f.projectID, TenantID: other, UserID: annsAgent, Source: service.MembershipSourceAdded, Role: service.RoleMember})
	require.ErrorIs(t, err, service.ErrManagedElsewhere)
	_, _, err = f.ms.AddMember(ctx, f.projectID, other, annsAgent)
	require.ErrorIs(t, err, service.ErrManagedElsewhere)
	_, _, err = f.ms.GrantMembership(ctx, &service.TenantMembership{ProjectID: f.projectID, TenantID: f.tenantID, UserID: annsAgent, Source: service.MembershipSourceAdded, Role: service.RoleMember})
	require.NoError(t, err, "the managing tenant is the agent's own")
	_, _, err = f.ms.GrantMembership(ctx, &service.TenantMembership{ProjectID: f.projectID, TenantID: other, UserID: personsAgent, Source: service.MembershipSourceAdded, Role: service.RoleMember})
	require.NoError(t, err, "a person's agent is unaffected")
}
