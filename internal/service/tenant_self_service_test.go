package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/jwt"
)

const (
	ssProject = "proj-1"
	ssOwnerID = "user-owner"
	ssOtherID = "user-other"
)

// selfServiceFixture is a MembershipService over linked tenant and
// membership fakes, with a recorded audit trail.
type selfServiceFixture struct {
	svc     *MembershipService
	tenants *fakeTenantStore
	members *fakeMembershipStore
	users   *fakeUserDirectory
	audit   *recordingAuditWriter
}

func newSelfServiceFixture(cfg *config.Config) *selfServiceFixture {
	mem, tnt := newFakeMembershipStore(), newFakeTenantStore()
	linkFakeTenantStores(tnt, mem)
	usr := newFakeUserDirectory()
	usr.byID[ssOwnerID] = &User{ID: ssOwnerID, Email: "owner@example.test", Status: StatusActive}
	usr.byID[ssOtherID] = &User{ID: ssOtherID, Email: "other@example.test", Status: StatusActive}
	w := newRecordingAuditWriter()
	svc := NewMembershipService(newFakeInvitationStore(), mem, tnt, usr, &recordingMailer{}, true, cfg, nil).
		WithAudit(audit.NewLogger(w, "test-tenant", nil))
	return &selfServiceFixture{svc: svc, tenants: tnt, members: mem, users: usr, audit: w}
}

// withTenantsProject is a request in ssProject with self-service tenants set
// as given.
func withTenantsProject(selfService bool) context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: ssProject,
		Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		Tenants:   ProjectTenantsConfig{SelfService: selfService},
	})
}

// ── CreateTenant ─────────────────────────────────────────────────────────

func TestCreateTenant_CreatesClaimedTenantOwnedByCaller(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})

	out, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, "  Acme Robotics  ", "203.0.113.7", "test-agent")
	require.NoError(t, err)

	require.NotNil(t, out.Tenant)
	assert.NotEmpty(t, out.Tenant.ID)
	assert.Equal(t, "Acme Robotics", out.Tenant.Name, "the name is trimmed")
	assert.Equal(t, TenantStatusClaimed, out.Tenant.Status)
	assert.Equal(t, ssOwnerID, out.Tenant.CreatedBy)

	require.NotNil(t, out.Membership)
	assert.Equal(t, out.Tenant.ID, out.Membership.TenantID)
	assert.Equal(t, ssOwnerID, out.Membership.UserID)
	assert.Equal(t, RoleOwner, out.Membership.Role)
	assert.Equal(t, MembershipStatusActive, out.Membership.Status)
	assert.Equal(t, MembershipSourceCreated, out.Membership.Source)

	// The membership is stored, so the caller administers the new tenant.
	stored, err := f.members.GetMembership(context.Background(), ssProject, out.Tenant.ID, ssOwnerID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, RoleOwner, stored.Role)

	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(string(audit.EventTenantCreated), ssOwnerID, ssOwnerID))
	assert.Equal(t, 1, f.audit.countByEventTypeAndDetail(string(audit.EventTenantCreated), "tenant_id", out.Tenant.ID))
}

func TestCreateTenant_SettingOffIsFailedPrecondition(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})

	_, err := f.svc.CreateTenant(withTenantsProject(false), ssOwnerID, "Acme", "", "")
	require.ErrorIs(t, err, ErrSelfServiceTenantsDisabled)
	assert.Empty(t, f.tenants.byID, "nothing is created")
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantCreated)))
}

func TestCreateTenant_Unauthenticated(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})

	_, err := f.svc.CreateTenant(withTenantsProject(true), "", "Acme", "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)

	_, err = f.svc.CreateTenant(context.Background(), ssOwnerID, "Acme", "", "")
	require.ErrorIs(t, err, ErrPermissionDenied, "no project in scope")
	assert.Empty(t, f.tenants.byID)
}

func TestCreateTenant_RejectsBadNames(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	for name, in := range map[string]string{
		"blank":         "   ",
		"too long":      strings.Repeat("a", tenantNameMaxRunes+1),
		"control":       "Acme\x00Corp",
		"format":        "Acme\u202eCorp",
		"invalid UTF-8": "Acme\xff",
	} {
		_, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, in, "", "")
		require.ErrorIs(t, err, ErrInvalidArgument, name)
	}
	assert.Empty(t, f.tenants.byID)

	// Exactly the limit is accepted, counted in characters, not bytes.
	_, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, strings.Repeat("é", tenantNameMaxRunes), "", "")
	require.NoError(t, err)
}

func TestCreateTenant_RefusesAccountsThatCannotOwn(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	f.users.byID["anon"] = &User{ID: "anon", IsAnonymous: true, Status: StatusActive}
	f.users.byID["agent"] = &User{ID: "agent", Kind: UserKindAgent, OwnerUserID: ssOwnerID, Status: StatusActive}
	f.users.byID["merged"] = &User{ID: "merged", Email: "m@example.test", MergedIntoUserID: ssOwnerID, Status: StatusActive}
	f.users.byID["inactive"] = &User{ID: "inactive", Email: "i@example.test", Status: StatusDeactivated}

	for _, id := range []string{"anon", "agent", "merged", "inactive"} {
		_, err := f.svc.CreateTenant(withTenantsProject(true), id, "Acme", "", "")
		require.ErrorIs(t, err, ErrPermissionDenied, id)
	}
	_, err := f.svc.CreateTenant(withTenantsProject(true), "user-missing", "Acme", "", "")
	require.ErrorIs(t, err, ErrNotFound)
	assert.Empty(t, f.tenants.byID)
}

func TestCreateTenant_PerUserLimit(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{SelfServiceTenantsMaxPerUser: 2, SelfServiceTenantsWindowSeconds: 3600})
	ctx := withTenantsProject(true)

	for i := 0; i < 2; i++ {
		_, err := f.svc.CreateTenant(ctx, ssOwnerID, "Acme", "", "")
		require.NoError(t, err)
	}
	_, err := f.svc.CreateTenant(ctx, ssOwnerID, "Acme", "", "")
	require.ErrorIs(t, err, ErrTenantCreationLimited)
	assert.Len(t, f.tenants.byID, 2)
	assert.Equal(t, 1, f.audit.countByEventTypeAndDetail(string(audit.EventTenantCreated), "reason", auditReasonCreationLimit),
		"the refused attempt is in the trail")

	// The limit is per user.
	_, err = f.svc.CreateTenant(ctx, ssOtherID, "Other", "", "")
	require.NoError(t, err)
}

func TestCreateTenant_LimitCountsOnlyTheWindow(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{SelfServiceTenantsMaxPerUser: 1, SelfServiceTenantsWindowSeconds: 3600})
	f.tenants.put(&Tenant{
		ID: "old", ProjectID: ssProject, Name: "Old", Status: TenantStatusClaimed, CreatedBy: ssOwnerID,
		CreatedAtMs: time.Now().Add(-2 * time.Hour).UnixMilli(),
	})

	_, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, "New", "", "")
	require.NoError(t, err, "a tenant created before the window does not count")

	_, err = f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, "Newer", "", "")
	require.ErrorIs(t, err, ErrTenantCreationLimited)
}

func TestCreateTenant_StoreErrorPropagates(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	boom := errors.New("store down")
	f.tenants.createErr = boom

	_, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, "Acme", "", "")
	require.ErrorIs(t, err, boom)
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantCreated)))
}

func TestCreateTenant_NilConfigUsesDefaultLimit(t *testing.T) {
	f := newSelfServiceFixture(nil)
	for i := 0; i < config.DefaultSelfServiceTenantsMaxPerUser; i++ {
		_, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, "Acme", "", "")
		require.NoError(t, err)
	}
	_, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, "Acme", "", "")
	require.ErrorIs(t, err, ErrTenantCreationLimited)
}

func TestCreateTenant_WithoutAuditRecordsNothing(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	f.svc.WithAudit(nil)
	_, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, "Acme", "", "")
	require.NoError(t, err)
}

// ── ListMyTenants ────────────────────────────────────────────────────────

func TestListMyTenants_OnlyTheCallersActiveTenants(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	ctx := context.Background()
	seed := func(id, name, status string) {
		f.tenants.put(&Tenant{ID: id, ProjectID: ssProject, Name: name, Status: status})
	}
	join := func(tenantID, userID, role, status string) {
		_, err := f.members.UpsertMembership(ctx, &TenantMembership{
			ProjectID: ssProject, TenantID: tenantID, UserID: userID,
			Source: MembershipSourceInvited, Role: role, Status: status,
		})
		require.NoError(t, err)
	}
	seed("t-b", "Beta", TenantStatusClaimed)
	seed("t-a", "Alpha", TenantStatusClaimed)
	seed("t-susp", "Suspended Co", TenantStatusSuspended)
	seed("t-left", "Left Co", TenantStatusClaimed)
	seed("t-others", "Others Co", TenantStatusClaimed)
	join("t-b", ssOwnerID, RoleMember, MembershipStatusActive)
	join("t-a", ssOwnerID, RoleAdmin, MembershipStatusActive)
	join("t-susp", ssOwnerID, RoleOwner, MembershipStatusActive)
	join("t-left", ssOwnerID, RoleMember, MembershipStatusInactive)
	join("t-others", ssOtherID, RoleOwner, MembershipStatusActive)
	// The same tenant id under another project is not this project's.
	f.tenants.put(&Tenant{ID: "t-x", ProjectID: "proj-2", Name: "Elsewhere", Status: TenantStatusClaimed})
	_, err := f.members.UpsertMembership(ctx, &TenantMembership{
		ProjectID: "proj-2", TenantID: "t-x", UserID: ssOwnerID,
		Source: MembershipSourceInvited, Role: RoleMember, Status: MembershipStatusActive,
	})
	require.NoError(t, err)

	got, err := f.svc.ListMyTenants(withTenantsProject(false), ssOwnerID)
	require.NoError(t, err)
	assert.Equal(t, []*UserTenant{
		{TenantID: "t-a", Name: "Alpha", Role: RoleAdmin},
		{TenantID: "t-b", Name: "Beta", Role: RoleMember},
	}, got, "ordered by name; suspended tenants, ended memberships, other users and other projects left out")
}

func TestListMyTenants_IncludesACreatedTenant(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	out, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, "Acme", "", "")
	require.NoError(t, err)

	got, err := f.svc.ListMyTenants(withTenantsProject(true), ssOwnerID)
	require.NoError(t, err)
	assert.Equal(t, []*UserTenant{{TenantID: out.Tenant.ID, Name: "Acme", Role: RoleOwner}}, got)

	others, err := f.svc.ListMyTenants(withTenantsProject(true), ssOtherID)
	require.NoError(t, err)
	assert.Empty(t, others)
}

func TestListMyTenants_RequiresCallerAndProject(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	_, err := f.svc.ListMyTenants(withTenantsProject(true), "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = f.svc.ListMyTenants(context.Background(), ssOwnerID)
	require.ErrorIs(t, err, ErrPermissionDenied)

	boom := errors.New("store down")
	f.members.listErr = boom
	_, err = f.svc.ListMyTenants(withTenantsProject(true), ssOwnerID)
	require.ErrorIs(t, err, boom)
}

// ── RefreshTokenInTenant ─────────────────────────────────────────────────

// selectionFixture is an AuthService whose tenant selection reads linked
// tenant and membership fakes in the default project.
type selectionFixture struct {
	svc     *AuthService
	tenants *fakeTenantStore
	members *fakeMembershipStore
	user    *User
	refresh string
}

func newSelectionFixture(t *testing.T) *selectionFixture {
	t.Helper()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	mem, tnt := newFakeMembershipStore(), newFakeTenantStore()
	linkFakeTenantStores(tnt, mem)
	svc.WithTenantSelection(mem)

	signup, err := svc.PasswordSignup(context.Background(), "member@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	return &selectionFixture{svc: svc, tenants: tnt, members: mem, user: signup.User, refresh: signup.RefreshToken}
}

func (f *selectionFixture) project() string { return f.svc.cfg.DefaultProjectID }

func (f *selectionFixture) seedTenant(t *testing.T, id, tenantStatus, membershipStatus string) {
	t.Helper()
	f.tenants.put(&Tenant{ID: id, ProjectID: f.project(), Name: id, Status: tenantStatus})
	_, err := f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: f.project(), TenantID: id, UserID: f.user.ID,
		Source: MembershipSourceInvited, Role: RoleMember, Status: membershipStatus,
	})
	require.NoError(t, err)
}

func (f *selectionFixture) tenantClaim(t *testing.T, access string) string {
	t.Helper()
	claims, err := jwt.VerifyAccessToken(access, f.svc.signer, "", "", false)
	require.NoError(t, err)
	return claims.Tenant
}

func TestRefreshTokenInTenant_ActiveMemberGetsTenantClaim(t *testing.T) {
	f := newSelectionFixture(t)
	f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusActive)

	_, access, refresh, err := f.svc.RefreshTokenInTenant(context.Background(), f.refresh, "t-acme", "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, refresh)
	assert.Equal(t, "t-acme", f.tenantClaim(t, access))
}

func TestRefreshTokenInTenant_OmittedKeepsDefault(t *testing.T) {
	f := newSelectionFixture(t)
	f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusActive)

	for _, sel := range []string{"", "   "} {
		_, access, refresh, err := f.svc.RefreshTokenInTenant(context.Background(), f.refresh, sel, "", "")
		require.NoError(t, err)
		assert.Equal(t, f.svc.tenantID(context.Background()), f.tenantClaim(t, access))
		f.refresh = refresh
	}
}

// Every refusal leaves the refresh token unspent: the same token still
// rotates without a selection, which a consumed token would not (it would
// trip replay detection instead).
func TestRefreshTokenInTenant_RefusalsDoNotConsumeTheToken(t *testing.T) {
	cases := map[string]func(f *selectionFixture){
		"not a member":       func(*selectionFixture) {},
		"suspended member":   func(f *selectionFixture) { f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusInactive) },
		"pending member":     func(f *selectionFixture) { f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusPending) },
		"suspended tenant":   func(f *selectionFixture) { f.seedTenant(t, "t-acme", TenantStatusSuspended, MembershipStatusActive) },
		"latent tenant":      func(f *selectionFixture) { f.seedTenant(t, "t-acme", TenantStatusLatent, MembershipStatusActive) },
		"no selection store": func(f *selectionFixture) { f.svc.WithTenantSelection(nil) },
		"another project's tenant": func(f *selectionFixture) {
			f.tenants.put(&Tenant{ID: "t-acme", ProjectID: "proj-elsewhere", Name: "x", Status: TenantStatusClaimed})
			_, _ = f.members.UpsertMembership(context.Background(), &TenantMembership{
				ProjectID: "proj-elsewhere", TenantID: "t-acme", UserID: f.user.ID,
				Source: MembershipSourceInvited, Role: RoleMember, Status: MembershipStatusActive,
			})
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSelectionFixture(t)
			setup(f)

			_, access, refresh, err := f.svc.RefreshTokenInTenant(context.Background(), f.refresh, "t-acme", "", "")
			require.ErrorIs(t, err, ErrPermissionDenied)
			assert.Empty(t, access, "no token on a refusal")
			assert.Empty(t, refresh)

			_, access, _, err = f.svc.RefreshToken(context.Background(), f.refresh, "", "")
			require.NoError(t, err, "the refused refresh token still rotates")
			assert.Equal(t, f.svc.tenantID(context.Background()), f.tenantClaim(t, access))
		})
	}
}

func TestRefreshTokenInTenant_ReaderErrorDoesNotConsume(t *testing.T) {
	f := newSelectionFixture(t)
	boom := errors.New("store down")
	f.members.getErr = boom

	_, _, _, err := f.svc.RefreshTokenInTenant(context.Background(), f.refresh, "t-acme", "", "")
	require.ErrorIs(t, err, boom)

	f.members.getErr = nil
	_, _, _, err = f.svc.RefreshToken(context.Background(), f.refresh, "", "")
	require.NoError(t, err)
}

// Switching is a refresh naming another tenant; each one re-issues the
// token, and the selection is not remembered.
func TestRefreshTokenInTenant_SwitchingReissues(t *testing.T) {
	f := newSelectionFixture(t)
	f.seedTenant(t, "t-one", TenantStatusClaimed, MembershipStatusActive)
	f.seedTenant(t, "t-two", TenantStatusClaimed, MembershipStatusActive)
	ctx := context.Background()

	_, access1, refresh1, err := f.svc.RefreshTokenInTenant(ctx, f.refresh, "t-one", "", "")
	require.NoError(t, err)
	assert.Equal(t, "t-one", f.tenantClaim(t, access1))

	_, access2, refresh2, err := f.svc.RefreshTokenInTenant(ctx, refresh1, "t-two", "", "")
	require.NoError(t, err)
	assert.Equal(t, "t-two", f.tenantClaim(t, access2))
	assert.NotEqual(t, access1, access2)
	assert.NotEqual(t, refresh1, refresh2, "the refresh token rotates on a switch")

	_, access3, _, err := f.svc.RefreshTokenInTenant(ctx, refresh2, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, f.svc.tenantID(ctx), f.tenantClaim(t, access3), "no selection returns to the default")

	// The rotated-away token is spent.
	_, _, _, err = f.svc.RefreshTokenInTenant(ctx, refresh1, "t-two", "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
}

// A membership that ends stops the next refresh into that tenant.
func TestRefreshTokenInTenant_EndedMembershipStopsNextRefresh(t *testing.T) {
	f := newSelectionFixture(t)
	f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusActive)
	ctx := context.Background()

	_, _, refresh, err := f.svc.RefreshTokenInTenant(ctx, f.refresh, "t-acme", "", "")
	require.NoError(t, err)

	require.NoError(t, f.members.RemoveMembership(ctx, f.project(), "t-acme", f.user.ID))
	_, _, _, err = f.svc.RefreshTokenInTenant(ctx, refresh, "t-acme", "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
}
