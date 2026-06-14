package service

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/email"
)

// ── Fakes specific to MembershipService ──────────────────────────────────
//
// fakeMembershipStore / fakeTenantStore / withProject are reused from
// domain_test.go in this same package; only the invitation store, user
// directory, and a recording mailer are new here.

// fakeInvitationStore is an in-memory InvitationStore that mirrors the
// postgres store's revoke-then-insert one-open-invite semantics.
type fakeInvitationStore struct {
	byID      map[string]*TenantInvitation
	createErr error
	getErr    error
	setErr    error
	listErr   error
	nextID    int
}

func newFakeInvitationStore() *fakeInvitationStore {
	return &fakeInvitationStore{byID: map[string]*TenantInvitation{}}
}

func (f *fakeInvitationStore) key(projectID, id string) string { return projectID + "/" + id }

func (f *fakeInvitationStore) CreateInvitation(_ context.Context, inv *TenantInvitation) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	// Revoke any existing pending invite for the same (project, tenant, lower(email)).
	for _, existing := range f.byID {
		if existing.ProjectID == inv.ProjectID && existing.TenantID == inv.TenantID &&
			strings.EqualFold(existing.Email, inv.Email) && existing.Status == InvitationStatusPending {
			existing.Status = InvitationStatusRevoked
		}
	}
	f.nextID++
	id := inv.ID
	if id == "" {
		id = "inv-" + strconv.Itoa(f.nextID)
	}
	role := inv.Role
	if role == "" {
		role = RoleMember
	}
	stored := *inv
	stored.ID = id
	stored.Role = role
	stored.Status = InvitationStatusPending
	f.byID[f.key(inv.ProjectID, id)] = &stored
	inv.ID = id
	inv.Role = role
	inv.Status = InvitationStatusPending
	return id, nil
}

func (f *fakeInvitationStore) GetInvitationByTokenHash(_ context.Context, projectID, tokenHash string) (*TenantInvitation, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	for _, inv := range f.byID {
		if inv.ProjectID == projectID && inv.TokenHash == tokenHash {
			out := *inv
			return &out, nil
		}
	}
	return nil, nil
}

func (f *fakeInvitationStore) SetInvitationStatus(_ context.Context, projectID, invitationID, status string, acceptedAtMs int64) error {
	if f.setErr != nil {
		return f.setErr
	}
	inv, ok := f.byID[f.key(projectID, invitationID)]
	if !ok {
		return nil
	}
	inv.Status = status
	if status == InvitationStatusAccepted {
		if acceptedAtMs == 0 {
			acceptedAtMs = 1
		}
		inv.AcceptedAtMs = acceptedAtMs
	}
	return nil
}

func (f *fakeInvitationStore) ListInvitationsForTenant(_ context.Context, projectID, tenantID string) ([]*TenantInvitation, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []*TenantInvitation
	for _, inv := range f.byID {
		if inv.ProjectID == projectID && inv.TenantID == tenantID {
			cp := *inv
			out = append(out, &cp)
		}
	}
	return out, nil
}

var _ InvitationStore = (*fakeInvitationStore)(nil)

// fakeUserDirectory resolves users by id for the email-match policy.
type fakeUserDirectory struct {
	byID   map[string]*User
	getErr error
}

func newFakeUserDirectory() *fakeUserDirectory {
	return &fakeUserDirectory{byID: map[string]*User{}}
}

func (d *fakeUserDirectory) put(id, emailAddr string) {
	d.byID[id] = &User{ID: id, Email: emailAddr}
}

func (d *fakeUserDirectory) GetUser(_ context.Context, userID string) (*User, error) {
	if d.getErr != nil {
		return nil, d.getErr
	}
	u, ok := d.byID[userID]
	if !ok {
		return nil, nil
	}
	out := *u
	return &out, nil
}

var _ UserDirectory = (*fakeUserDirectory)(nil)

// recordingMailer captures sent messages so a test can assert the invitation
// email was dispatched. It never fails (best-effort send semantics).
type recordingMailer struct {
	mu   sync.Mutex
	sent []email.Message
}

func (m *recordingMailer) Send(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

func (m *recordingMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func (m *recordingMailer) last() email.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		return email.Message{}
	}
	return m.sent[len(m.sent)-1]
}

var _ email.Transport = (*recordingMailer)(nil)

// ── Harness ──────────────────────────────────────────────────────────────

type membershipFixture struct {
	svc         *MembershipService
	invitations *fakeInvitationStore
	memberships *fakeMembershipStore
	tenants     *fakeTenantStore
	users       *fakeUserDirectory
	mailer      *recordingMailer
}

// newMembershipFixture builds a MembershipService with a configured mailer
// (so the raw token is NOT returned and emails are recorded). Tests needing
// the no-mailer path use newMembershipFixtureNoMail.
func newMembershipFixture() *membershipFixture {
	return newMembershipFixtureWith(true)
}

func newMembershipFixtureNoMail() *membershipFixture {
	return newMembershipFixtureWith(false)
}

func newMembershipFixtureWith(mailerConfigured bool) *membershipFixture {
	inv := newFakeInvitationStore()
	mem := newFakeMembershipStore()
	tnt := newFakeTenantStore()
	usr := newFakeUserDirectory()
	mailer := &recordingMailer{}
	svc := NewMembershipService(inv, mem, tnt, usr, mailer, mailerConfigured, &config.Config{}, nil)
	return &membershipFixture{
		svc: svc, invitations: inv, memberships: mem, tenants: tnt, users: usr, mailer: mailer,
	}
}

// seedAdmin makes userID an active owner of (project, tenant).
func (f *membershipFixture) seedAdmin(projectID, tenantID, userID string) {
	_, _ = f.memberships.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: userID,
		Source: MembershipSourceAdded, Role: RoleOwner, Status: MembershipStatusActive,
	})
}

func (f *membershipFixture) seedMember(projectID, tenantID, userID, role string) {
	_, _ = f.memberships.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: userID,
		Source: MembershipSourceAdded, Role: role, Status: MembershipStatusActive,
	})
}

const (
	mInvitee     = "invitee@acme.com"
	mInviteeID   = "user-invitee"
	mAdminID     = "user-admin"
	mTestProject = "proj-1"
	mTestTenant  = "tenant-1"
)

// ── CreateTenantInvitation ───────────────────────────────────────────────

func TestCreateTenantInvitation_AdminInvitesAndEmails(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)

	out, err := f.svc.CreateTenantInvitation(withProject(mTestProject), mAdminID, mTestTenant, "Invitee@ACME.com", RoleAdmin)
	require.NoError(t, err)
	require.NotNil(t, out.Invitation)
	require.NotEmpty(t, out.Invitation.ID)
	require.Equal(t, mInvitee, out.Invitation.Email, "email normalized to lower-case")
	require.Equal(t, RoleAdmin, out.Invitation.Role)
	require.Equal(t, InvitationStatusPending, out.Invitation.Status)
	require.Equal(t, mAdminID, out.Invitation.InvitedBy)
	require.NotZero(t, out.Invitation.ExpiresAtMs)

	// With a mailer configured the raw token is NOT returned; it is emailed.
	require.Empty(t, out.RawToken, "raw token must not be returned when a mailer is configured")
	require.Equal(t, 1, f.mailer.count(), "an invitation email was dispatched")
	require.Equal(t, mInvitee, f.mailer.last().To)

	// The stored token hash must not equal any raw token in the response.
	require.NotEmpty(t, out.Invitation.TokenHash)
}

func TestCreateTenantInvitation_NoMailerReturnsRawToken(t *testing.T) {
	f := newMembershipFixtureNoMail()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)

	out, err := f.svc.CreateTenantInvitation(withProject(mTestProject), mAdminID, mTestTenant, mInvitee, "")
	require.NoError(t, err)
	require.Equal(t, RoleMember, out.Invitation.Role, "blank role defaults to member")
	require.NotEmpty(t, out.RawToken, "raw token returned when no mailer is configured")

	// The returned raw token must hash to the stored token hash.
	require.Equal(t, out.Invitation.TokenHash, sha256Hex(out.RawToken))
}

func TestCreateTenantInvitation_RejectsNonAdmin(t *testing.T) {
	f := newMembershipFixture()
	// caller is only a plain member, not admin/owner.
	f.seedMember(mTestProject, mTestTenant, mAdminID, RoleMember)

	_, err := f.svc.CreateTenantInvitation(withProject(mTestProject), mAdminID, mTestTenant, mInvitee, RoleMember)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestCreateTenantInvitation_RejectsNonMember(t *testing.T) {
	f := newMembershipFixture()
	_, err := f.svc.CreateTenantInvitation(withProject(mTestProject), mAdminID, mTestTenant, mInvitee, RoleMember)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestCreateTenantInvitation_RejectsBadInput(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	ctx := withProject(mTestProject)

	_, err := f.svc.CreateTenantInvitation(ctx, mAdminID, "", mInvitee, RoleMember)
	require.ErrorIs(t, err, ErrInvalidArgument, "blank tenant")

	_, err = f.svc.CreateTenantInvitation(ctx, mAdminID, mTestTenant, "not-an-email", RoleMember)
	require.ErrorIs(t, err, ErrInvalidArgument, "email without @")

	_, err = f.svc.CreateTenantInvitation(ctx, mAdminID, mTestTenant, "   ", RoleMember)
	require.ErrorIs(t, err, ErrInvalidArgument, "blank email")

	_, err = f.svc.CreateTenantInvitation(ctx, mAdminID, mTestTenant, mInvitee, "superuser")
	require.ErrorIs(t, err, ErrInvalidArgument, "unknown role")
}

func TestCreateTenantInvitation_RejectsMissingProjectAndCaller(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)

	_, err := f.svc.CreateTenantInvitation(context.Background(), mAdminID, mTestTenant, mInvitee, RoleMember)
	require.ErrorIs(t, err, ErrPermissionDenied, "no project")

	_, err = f.svc.CreateTenantInvitation(withProject(mTestProject), "", mTestTenant, mInvitee, RoleMember)
	require.ErrorIs(t, err, ErrUnauthenticated, "no caller")
}

func TestCreateTenantInvitation_OneOpenInviteRevokesPrior(t *testing.T) {
	f := newMembershipFixtureNoMail()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	ctx := withProject(mTestProject)

	first, err := f.svc.CreateTenantInvitation(ctx, mAdminID, mTestTenant, mInvitee, RoleMember)
	require.NoError(t, err)

	second, err := f.svc.CreateTenantInvitation(ctx, mAdminID, mTestTenant, mInvitee, RoleAdmin)
	require.NoError(t, err)
	require.NotEqual(t, first.Invitation.ID, second.Invitation.ID)

	// Only the second invite is pending; the first is revoked. List confirms.
	invs, err := f.svc.ListTenantInvitations(ctx, mAdminID, mTestTenant)
	require.NoError(t, err)
	statusByID := map[string]string{}
	for _, inv := range invs {
		statusByID[inv.ID] = inv.Status
	}
	require.Equal(t, InvitationStatusRevoked, statusByID[first.Invitation.ID])
	require.Equal(t, InvitationStatusPending, statusByID[second.Invitation.ID])

	// The first (revoked) token can no longer be accepted.
	f.users.put(mInviteeID, mInvitee)
	_, err = f.svc.AcceptTenantInvitation(ctx, mInviteeID, first.RawToken)
	require.ErrorIs(t, err, ErrPermissionDenied, "a revoked invite is not redeemable")
}

func TestCreateTenantInvitation_PropagatesStoreError(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	f.invitations.createErr = errBoom

	_, err := f.svc.CreateTenantInvitation(withProject(mTestProject), mAdminID, mTestTenant, mInvitee, RoleMember)
	require.ErrorIs(t, err, errBoom)
}

// ── AcceptTenantInvitation ───────────────────────────────────────────────

// seedInvite creates a pending invite for mInvitee and returns the raw token.
func (f *membershipFixture) seedInvite(t *testing.T) string {
	t.Helper()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	out, err := f.svc.CreateTenantInvitation(withProject(mTestProject), mAdminID, mTestTenant, mInvitee, RoleAdmin)
	require.NoError(t, err)
	// Recover the raw token regardless of mailer config: re-derive it is not
	// possible (hash is one-way), so seedInvite always uses the no-mail path.
	require.NotEmpty(t, out.RawToken, "seedInvite requires the no-mail fixture")
	return out.RawToken
}

func TestAcceptTenantInvitation_MatchingEmailBecomesMember(t *testing.T) {
	f := newMembershipFixtureNoMail()
	rawToken := f.seedInvite(t)
	f.users.put(mInviteeID, "Invitee@Acme.com") // case-insensitive match
	ctx := withProject(mTestProject)

	m, err := f.svc.AcceptTenantInvitation(ctx, mInviteeID, rawToken)
	require.NoError(t, err)
	require.Equal(t, mInviteeID, m.UserID)
	require.Equal(t, RoleAdmin, m.Role, "membership takes the invitation's role")
	require.Equal(t, MembershipSourceInvited, m.Source)
	require.Equal(t, MembershipStatusActive, m.Status)

	// The membership is persisted.
	stored, _ := f.memberships.GetMembership(context.Background(), mTestProject, mTestTenant, mInviteeID)
	require.NotNil(t, stored)
	require.Equal(t, RoleAdmin, stored.Role)

	// The invitation is marked accepted.
	invs, _ := f.invitations.ListInvitationsForTenant(context.Background(), mTestProject, mTestTenant)
	require.Len(t, invs, 1)
	require.Equal(t, InvitationStatusAccepted, invs[0].Status)
	require.NotZero(t, invs[0].AcceptedAtMs)
}

func TestAcceptTenantInvitation_WrongEmailDenied(t *testing.T) {
	f := newMembershipFixtureNoMail()
	rawToken := f.seedInvite(t)
	f.users.put("user-eve", "eve@evil.com") // does NOT match the invitee email
	ctx := withProject(mTestProject)

	_, err := f.svc.AcceptTenantInvitation(ctx, "user-eve", rawToken)
	require.ErrorIs(t, err, ErrPermissionDenied)

	// No membership was created for the wrong caller.
	stored, _ := f.memberships.GetMembership(context.Background(), mTestProject, mTestTenant, "user-eve")
	require.Nil(t, stored)
	// The invitation remains pending (not consumed by a failed accept).
	invs, _ := f.invitations.ListInvitationsForTenant(context.Background(), mTestProject, mTestTenant)
	require.Equal(t, InvitationStatusPending, invs[0].Status)
}

func TestAcceptTenantInvitation_UnknownTokenNotFound(t *testing.T) {
	f := newMembershipFixtureNoMail()
	f.users.put(mInviteeID, mInvitee)

	_, err := f.svc.AcceptTenantInvitation(withProject(mTestProject), mInviteeID, "deadbeef")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestAcceptTenantInvitation_ExpiredTokenDeniedAndMarkedExpired(t *testing.T) {
	f := newMembershipFixtureNoMail()
	rawToken := f.seedInvite(t)
	f.users.put(mInviteeID, mInvitee)

	// Fast-forward time past the invitation expiry.
	f.svc.nowFunc = func() time.Time { return time.Now().Add(defaultInvitationTTL + time.Hour) }

	_, err := f.svc.AcceptTenantInvitation(withProject(mTestProject), mInviteeID, rawToken)
	require.ErrorIs(t, err, ErrPermissionDenied)

	invs, _ := f.invitations.ListInvitationsForTenant(context.Background(), mTestProject, mTestTenant)
	require.Equal(t, InvitationStatusExpired, invs[0].Status, "expired invite is marked expired")
}

func TestAcceptTenantInvitation_DoubleAcceptDenied(t *testing.T) {
	f := newMembershipFixtureNoMail()
	rawToken := f.seedInvite(t)
	f.users.put(mInviteeID, mInvitee)
	ctx := withProject(mTestProject)

	_, err := f.svc.AcceptTenantInvitation(ctx, mInviteeID, rawToken)
	require.NoError(t, err)

	// Second redemption of the now-accepted token is rejected.
	_, err = f.svc.AcceptTenantInvitation(ctx, mInviteeID, rawToken)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestAcceptTenantInvitation_RejectsMissingProjectCallerToken(t *testing.T) {
	f := newMembershipFixtureNoMail()

	_, err := f.svc.AcceptTenantInvitation(context.Background(), mInviteeID, "tok")
	require.ErrorIs(t, err, ErrPermissionDenied, "no project")

	_, err = f.svc.AcceptTenantInvitation(withProject(mTestProject), "", "tok")
	require.ErrorIs(t, err, ErrUnauthenticated, "no caller")

	_, err = f.svc.AcceptTenantInvitation(withProject(mTestProject), mInviteeID, "")
	require.ErrorIs(t, err, ErrInvalidArgument, "no token")
}

func TestAcceptTenantInvitation_UnknownCallerNotFound(t *testing.T) {
	f := newMembershipFixtureNoMail()
	rawToken := f.seedInvite(t)
	// caller id has no user row.

	_, err := f.svc.AcceptTenantInvitation(withProject(mTestProject), "ghost", rawToken)
	require.ErrorIs(t, err, ErrNotFound)
}

// ── ListTenantInvitations / ListTenantMembers ────────────────────────────

func TestListTenantInvitations_AdminGated(t *testing.T) {
	f := newMembershipFixtureNoMail()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	ctx := withProject(mTestProject)
	_, err := f.svc.CreateTenantInvitation(ctx, mAdminID, mTestTenant, mInvitee, RoleMember)
	require.NoError(t, err)

	invs, err := f.svc.ListTenantInvitations(ctx, mAdminID, mTestTenant)
	require.NoError(t, err)
	require.Len(t, invs, 1)

	// A non-admin caller is denied.
	_, err = f.svc.ListTenantInvitations(ctx, "stranger", mTestTenant)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestListTenantMembers_AdminGated(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	f.seedMember(mTestProject, mTestTenant, "user-bob", RoleMember)
	ctx := withProject(mTestProject)

	members, err := f.svc.ListTenantMembers(ctx, mAdminID, mTestTenant)
	require.NoError(t, err)
	require.Len(t, members, 2)

	_, err = f.svc.ListTenantMembers(ctx, "stranger", mTestTenant)
	require.ErrorIs(t, err, ErrPermissionDenied)
}

// ── RemoveTenantMember ───────────────────────────────────────────────────

func TestRemoveTenantMember_RemovesNonOwner(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	f.seedMember(mTestProject, mTestTenant, "user-bob", RoleMember)
	ctx := withProject(mTestProject)

	err := f.svc.RemoveTenantMember(ctx, mAdminID, mTestTenant, "user-bob")
	require.NoError(t, err)

	stored, _ := f.memberships.GetMembership(context.Background(), mTestProject, mTestTenant, "user-bob")
	require.Nil(t, stored)
}

func TestRemoveTenantMember_LastOwnerGuard(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID) // the only owner
	ctx := withProject(mTestProject)

	// Removing the sole owner (even self-removal) is refused.
	err := f.svc.RemoveTenantMember(ctx, mAdminID, mTestTenant, mAdminID)
	require.ErrorIs(t, err, ErrLastOwner)

	// The owner is still present.
	stored, _ := f.memberships.GetMembership(context.Background(), mTestProject, mTestTenant, mAdminID)
	require.NotNil(t, stored)
}

func TestRemoveTenantMember_OwnerRemovableWhenAnotherOwnerRemains(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	f.seedMember(mTestProject, mTestTenant, "user-co-owner", RoleOwner)
	ctx := withProject(mTestProject)

	// Self-removal is fine because another active owner remains.
	err := f.svc.RemoveTenantMember(ctx, mAdminID, mTestTenant, mAdminID)
	require.NoError(t, err)

	stored, _ := f.memberships.GetMembership(context.Background(), mTestProject, mTestTenant, mAdminID)
	require.Nil(t, stored)
	// The co-owner survives.
	coOwner, _ := f.memberships.GetMembership(context.Background(), mTestProject, mTestTenant, "user-co-owner")
	require.NotNil(t, coOwner)
}

func TestRemoveTenantMember_RejectsNonAdmin(t *testing.T) {
	f := newMembershipFixture()
	f.seedMember(mTestProject, mTestTenant, "user-bob", RoleMember)

	err := f.svc.RemoveTenantMember(withProject(mTestProject), "user-bob", mTestTenant, "user-bob")
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestRemoveTenantMember_UnknownTargetIsNoOp(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)

	err := f.svc.RemoveTenantMember(withProject(mTestProject), mAdminID, mTestTenant, "nobody")
	require.NoError(t, err)
}

func TestRemoveTenantMember_RejectsBadInput(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	ctx := withProject(mTestProject)

	err := f.svc.RemoveTenantMember(ctx, mAdminID, "", "user-bob")
	require.ErrorIs(t, err, ErrInvalidArgument, "blank tenant")

	err = f.svc.RemoveTenantMember(ctx, mAdminID, mTestTenant, "")
	require.ErrorIs(t, err, ErrInvalidArgument, "blank user")

	err = f.svc.RemoveTenantMember(context.Background(), mAdminID, mTestTenant, "user-bob")
	require.ErrorIs(t, err, ErrPermissionDenied, "no project")

	err = f.svc.RemoveTenantMember(withProject(mTestProject), "", mTestTenant, "user-bob")
	require.ErrorIs(t, err, ErrUnauthenticated, "no caller")
}

// ── Constructor defaults ─────────────────────────────────────────────────

func TestNewMembershipService_DefaultsLogger(t *testing.T) {
	svc := NewMembershipService(
		newFakeInvitationStore(), newFakeMembershipStore(), newFakeTenantStore(),
		newFakeUserDirectory(), &recordingMailer{}, false, nil, nil,
	)
	require.NotNil(t, svc.logger, "a nil logger must default to a no-op")
	require.NotNil(t, svc.nowFunc)
	// invitationTTL falls back to the default when cfg is nil.
	require.Equal(t, defaultInvitationTTL, svc.invitationTTL())
}

func TestMembershipService_InvitationTTLFromConfig(t *testing.T) {
	cfg := &config.Config{TenantInvitationExpirySeconds: 3600}
	svc := NewMembershipService(
		newFakeInvitationStore(), newFakeMembershipStore(), newFakeTenantStore(),
		newFakeUserDirectory(), &recordingMailer{}, false, cfg, nil,
	)
	require.Equal(t, time.Hour, svc.invitationTTL())
}
