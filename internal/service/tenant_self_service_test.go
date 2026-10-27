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
	usr.set(ssProject, &User{ID: ssOwnerID, Email: "owner@example.test", Status: StatusActive, EmailVerified: true})
	usr.set(ssProject, &User{ID: ssOtherID, Email: "other@example.test", Status: StatusActive, EmailVerified: true})
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

// The caller is looked up in the request's project, where their account
// lives: a user of another project is found there, and only there.
func TestCreateTenant_ResolvesCallerInRequestProject(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	f.users.set("proj-2", &User{ID: "user-p2", Email: "p2@example.test", Status: StatusActive, EmailVerified: true})
	inProj2 := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "proj-2", Tenants: ProjectTenantsConfig{SelfService: true},
	})

	out, err := f.svc.CreateTenant(inProj2, "user-p2", "Acme", "", "")
	require.NoError(t, err)
	assert.Equal(t, "proj-2", out.Tenant.ProjectID)

	_, err = f.svc.CreateTenant(withTenantsProject(true), "user-p2", "Acme", "", "")
	require.ErrorIs(t, err, ErrNotFound, "not an account of the request's project")
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
	f.users.set(ssProject, &User{ID: "anon", IsAnonymous: true, Status: StatusActive})
	f.users.set(ssProject, &User{ID: "agent", Kind: UserKindAgent, OwnerUserID: ssOwnerID, Status: StatusActive})
	f.users.set(ssProject, &User{ID: "merged", Email: "m@example.test", MergedIntoUserID: ssOwnerID, Status: StatusActive})
	f.users.set(ssProject, &User{ID: "inactive", Email: "i@example.test", Status: StatusDeactivated})

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
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantCreated)), "the detached logger records nothing")
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
		{TenantID: "t-a", Name: "Alpha", Role: RoleAdmin, Source: MembershipSourceInvited},
		{TenantID: "t-b", Name: "Beta", Role: RoleMember, Source: MembershipSourceInvited},
	}, got, "ordered by name; suspended tenants, ended memberships, other users and other projects left out")
}

func TestListMyTenants_IncludesACreatedTenant(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	out, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, "Acme", "", "")
	require.NoError(t, err)

	got, err := f.svc.ListMyTenants(withTenantsProject(true), ssOwnerID)
	require.NoError(t, err)
	assert.Equal(t, []*UserTenant{{TenantID: out.Tenant.ID, Name: "Acme", Role: RoleOwner, Source: MembershipSourceCreated}}, got)

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

// ── RefreshToken ─────────────────────────────────────────────────

// selectionFixture is an AuthService whose tenant selection reads linked
// tenant and membership fakes in the default project.
type selectionFixture struct {
	svc     *AuthService
	repo    *fakeRepo
	tenants *fakeTenantStore
	members *fakeMembershipStore
	user    *User
	refresh string
}

func newSelectionFixture(t *testing.T) *selectionFixture {
	t.Helper()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	// A named project, as every deployment has one (app.prepareConfig): login
	// governance governs nothing in the empty project.
	svc.cfg.DefaultProjectID = "proj-select"
	mem, tnt := newFakeMembershipStore(), newFakeTenantStore()
	linkFakeTenantStores(tnt, mem)
	svc.WithTenantSelection(mem)

	signup, err := svc.PasswordSignup(context.Background(), "member@example.com", strongPW, "", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	return &selectionFixture{svc: svc, repo: repo, tenants: tnt, members: mem, user: signup.User, refresh: signup.RefreshToken}
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

func TestRefreshToken_ActiveMemberGetsTenantClaim(t *testing.T) {
	f := newSelectionFixture(t)
	f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusActive)

	_, access, refresh, err := f.svc.RefreshToken(context.Background(), f.refresh, "t-acme", "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, refresh)
	assert.Equal(t, "t-acme", f.tenantClaim(t, access))
}

func TestRefreshToken_OmittedKeepsDefault(t *testing.T) {
	f := newSelectionFixture(t)
	f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusActive)

	for _, sel := range []string{"", "   "} {
		_, access, refresh, err := f.svc.RefreshToken(context.Background(), f.refresh, sel, "", "")
		require.NoError(t, err)
		assert.Equal(t, f.svc.tenantID(context.Background()), f.tenantClaim(t, access))
		f.refresh = refresh
	}
}

// Every refusal leaves the refresh token unspent: the same token still
// rotates without a selection, which a consumed token would not (it would
// trip replay detection instead).
func TestRefreshToken_RefusalsDoNotConsumeTheToken(t *testing.T) {
	cases := map[string]func(t *testing.T, f *selectionFixture){
		"not a member": func(*testing.T, *selectionFixture) {},
		"suspended member": func(t *testing.T, f *selectionFixture) {
			t.Helper()
			f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusInactive)
		},
		"pending member": func(t *testing.T, f *selectionFixture) {
			t.Helper()
			f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusPending)
		},
		"suspended tenant": func(t *testing.T, f *selectionFixture) {
			t.Helper()
			f.seedTenant(t, "t-acme", TenantStatusSuspended, MembershipStatusActive)
		},
		"latent tenant": func(t *testing.T, f *selectionFixture) {
			t.Helper()
			f.seedTenant(t, "t-acme", TenantStatusLatent, MembershipStatusActive)
		},
		"another project's tenant": func(t *testing.T, f *selectionFixture) {
			t.Helper()
			f.tenants.put(&Tenant{ID: "t-acme", ProjectID: "proj-elsewhere", Name: "x", Status: TenantStatusClaimed})
			_, err := f.members.UpsertMembership(context.Background(), &TenantMembership{
				ProjectID: "proj-elsewhere", TenantID: "t-acme", UserID: f.user.ID,
				Source: MembershipSourceInvited, Role: RoleMember, Status: MembershipStatusActive,
			})
			require.NoError(t, err)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSelectionFixture(t)
			setup(t, f)

			_, access, refresh, err := f.svc.RefreshToken(context.Background(), f.refresh, "t-acme", "", "")
			require.ErrorIs(t, err, ErrPermissionDenied)
			requireSelectionRefusal(t, err, TenantSelectionNotAMember)
			assert.Empty(t, access, "no token on a refusal")
			assert.Empty(t, refresh)

			_, access, _, err = f.svc.RefreshToken(context.Background(), f.refresh, "", "", "")
			require.NoError(t, err, "the refused refresh token still rotates")
			assert.Equal(t, f.svc.tenantID(context.Background()), f.tenantClaim(t, access))
		})
	}
}

// An account refused over its own state takes that refusal, not a selection
// refusal: its token is spent and the session ends, whatever tenant it names.
func TestRefreshToken_InactiveAccountIsRefusedBeforeSelection(t *testing.T) {
	f := newSelectionFixture(t)
	ctx := context.Background()
	require.NoError(t, f.repo.UpdateUser(ctx, f.user.ID, map[string]any{"status": StatusDeactivated}))

	_, _, _, err := f.svc.RefreshToken(ctx, f.refresh, "t-not-a-member", "", "")
	require.ErrorIs(t, err, ErrAccountNotActive)
	assert.NotErrorIs(t, err, ErrPermissionDenied)
	var refusal *TenantSelectionRefusedError
	assert.NotErrorAs(t, err, &refusal, "an account-status refusal is not a selection refusal a client may retry")

	stored, err := f.repo.FindRefreshTokenByHashIncludingConsumed(ctx, hashRefreshToken(f.refresh))
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.NotZero(t, stored.ConsumedAtMs, "the account-status refusal spends the token")
}

func TestRefreshToken_ReaderErrorDoesNotConsume(t *testing.T) {
	f := newSelectionFixture(t)
	boom := errors.New("store down")
	f.members.getErr = boom

	_, _, _, err := f.svc.RefreshToken(context.Background(), f.refresh, "t-acme", "", "")
	require.ErrorIs(t, err, ErrUnavailable, "a failed read is not a verdict on the selection")
	requireSelectionRefusal(t, err, TenantSelectionUnavailable)
	assert.NotErrorIs(t, err, boom, "the store's error is logged, not returned")
	assert.NotContains(t, err.Error(), boom.Error())

	f.members.getErr = nil
	_, _, _, err = f.svc.RefreshToken(context.Background(), f.refresh, "", "", "")
	require.NoError(t, err)
}

// Switching is a refresh naming another tenant; each one re-issues the
// token, and the selection is not remembered.
func TestRefreshToken_SwitchingReissues(t *testing.T) {
	f := newSelectionFixture(t)
	f.seedTenant(t, "t-one", TenantStatusClaimed, MembershipStatusActive)
	f.seedTenant(t, "t-two", TenantStatusClaimed, MembershipStatusActive)
	ctx := context.Background()

	_, access1, refresh1, err := f.svc.RefreshToken(ctx, f.refresh, "t-one", "", "")
	require.NoError(t, err)
	assert.Equal(t, "t-one", f.tenantClaim(t, access1))

	_, access2, refresh2, err := f.svc.RefreshToken(ctx, refresh1, "t-two", "", "")
	require.NoError(t, err)
	assert.Equal(t, "t-two", f.tenantClaim(t, access2))
	assert.NotEqual(t, access1, access2)
	assert.NotEqual(t, refresh1, refresh2, "the refresh token rotates on a switch")

	_, access3, _, err := f.svc.RefreshToken(ctx, refresh2, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, f.svc.tenantID(ctx), f.tenantClaim(t, access3), "no selection returns to the default")

	// The rotated-away token is spent.
	_, _, _, err = f.svc.RefreshToken(ctx, refresh1, "t-two", "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
}

// A membership that ends stops the next refresh into that tenant.
func TestRefreshToken_EndedMembershipStopsNextRefresh(t *testing.T) {
	f := newSelectionFixture(t)
	f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusActive)
	ctx := context.Background()

	_, _, refresh, err := f.svc.RefreshToken(ctx, f.refresh, "t-acme", "", "")
	require.NoError(t, err)

	require.NoError(t, f.members.RemoveMembership(ctx, f.project(), "t-acme", f.user.ID))
	_, _, _, err = f.svc.RefreshToken(ctx, refresh, "t-acme", "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
}

// With selection off, naming a tenant is refused as not enabled — not as a
// membership refusal — and the refresh token is left unspent; naming the
// deployment's own tenant selects nothing and is not refused.
func TestRefreshToken_SelectionDisabled(t *testing.T) {
	f := newSelectionFixture(t)
	f.svc.WithTenantSelection(nil)
	ctx := context.Background()

	_, access, refresh, err := f.svc.RefreshToken(ctx, f.refresh, "t-acme", "", "")
	require.ErrorIs(t, err, ErrTenantSelectionDisabled)
	assert.NotErrorIs(t, err, ErrPermissionDenied)
	requireSelectionRefusal(t, err, TenantSelectionNotEnabled)
	assert.Empty(t, access)
	assert.Empty(t, refresh)

	_, access, refresh, err = f.svc.RefreshToken(ctx, f.refresh, " "+f.svc.tenantID(ctx)+" ", "", "")
	require.NoError(t, err, "the refused refresh token still rotates, and the default tenant is no selection")
	assert.Equal(t, f.svc.tenantID(ctx), f.tenantClaim(t, access))
	assert.NotEmpty(t, refresh)
}

// A membership that comes only from the email's domain does not let an
// unverified address act in the tenant; once the address is verified it does,
// and only while it is on a domain the tenant has verified.
func TestRefreshToken_DomainMembershipNeedsAVerifiedEmailOnTheDomain(t *testing.T) {
	f := newSelectionFixture(t)
	ctx := context.Background()
	f.tenants.put(&Tenant{ID: "t-acme", ProjectID: f.project(), Name: "Acme", Status: TenantStatusClaimed})
	f.members.verifyDomain(f.project(), "t-acme", "example.com")
	_, err := f.members.UpsertMembership(ctx, &TenantMembership{
		ProjectID: f.project(), TenantID: "t-acme", UserID: f.user.ID,
		Source: MembershipSourceDomain, Role: RoleMember, Status: MembershipStatusActive,
	})
	require.NoError(t, err)

	_, _, _, err = f.svc.RefreshToken(ctx, f.refresh, "t-acme", "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
	requireSelectionRefusal(t, err, TenantSelectionNotAMember)

	require.NoError(t, f.repo.UpdateUser(ctx, f.user.ID, map[string]any{"email_verified": true}))
	_, access, refresh, err := f.svc.RefreshToken(ctx, f.refresh, "t-acme", "", "")
	require.NoError(t, err)
	assert.Equal(t, "t-acme", f.tenantClaim(t, access))

	// A verified address on another domain is no member through this one.
	require.NoError(t, f.repo.UpdateUser(ctx, f.user.ID, map[string]any{"email": "member@elsewhere.test"}))
	_, _, _, err = f.svc.RefreshToken(ctx, refresh, "t-acme", "", "")
	require.ErrorIs(t, err, ErrPermissionDenied)
	requireSelectionRefusal(t, err, TenantSelectionNotAMember)
}

// requireSelectionRefusal asserts err is a TenantSelectionRefusedError for
// reason.
func requireSelectionRefusal(t *testing.T, err error, reason TenantSelectionRefusal) {
	t.Helper()
	var refusal *TenantSelectionRefusedError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, reason, refusal.Reason)
}

func TestListMyTenants_DomainMembershipNeedsAVerifiedEmailOnTheDomain(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	ctx := context.Background()
	f.tenants.put(&Tenant{ID: "t-dom", ProjectID: ssProject, Name: "Domain", Status: TenantStatusClaimed})
	f.members.verifyDomain(ssProject, "t-dom", "example.test")
	f.tenants.put(&Tenant{ID: "t-inv", ProjectID: ssProject, Name: "Invited", Status: TenantStatusClaimed})
	for id, source := range map[string]string{"t-dom": MembershipSourceDomain, "t-inv": MembershipSourceInvited} {
		_, err := f.members.UpsertMembership(ctx, &TenantMembership{
			ProjectID: ssProject, TenantID: id, UserID: ssOwnerID,
			Source: source, Role: RoleMember, Status: MembershipStatusActive,
		})
		require.NoError(t, err)
	}

	f.users.set(ssProject, &User{ID: ssOwnerID, Email: "owner@example.test", Status: StatusActive})
	got, err := f.svc.ListMyTenants(withTenantsProject(false), ssOwnerID)
	require.NoError(t, err)
	require.Len(t, got, 1, "the domain membership is left out while the email is unverified")
	assert.Equal(t, "t-inv", got[0].TenantID)

	// The domain is matched under FoldEmail, as users.email_domain stores it.
	f.users.set(ssProject, &User{ID: ssOwnerID, Email: "owner@EXAMPLE.test", Status: StatusActive, EmailVerified: true})
	got, err = f.svc.ListMyTenants(withTenantsProject(false), ssOwnerID)
	require.NoError(t, err)
	assert.Len(t, got, 2)

	f.users.set(ssProject, &User{ID: ssOwnerID, Email: "owner@elsewhere.test", Status: StatusActive, EmailVerified: true})
	got, err = f.svc.ListMyTenants(withTenantsProject(false), ssOwnerID)
	require.NoError(t, err)
	require.Len(t, got, 1, "a verified address off the tenant's domain is no member through it")
	assert.Equal(t, "t-inv", got[0].TenantID)

	boom := errors.New("directory down")
	f.users.getErr = boom
	_, err = f.svc.ListMyTenants(withTenantsProject(false), ssOwnerID)
	require.ErrorIs(t, err, boom)
	f.users.getErr = nil
	delete(f.users.byID, f.users.key(ssProject, ssOwnerID))
	_, err = f.svc.ListMyTenants(withTenantsProject(false), ssOwnerID)
	require.ErrorIs(t, err, ErrNotFound)
}

// The joiners Persian, the Indic scripts and emoji sequences need are kept;
// the bidirectional overrides that make one name render as another, and the
// line and paragraph separators that break the line it is shown on, are not.
func TestNormalizeText_FormattingCharacters(t *testing.T) {
	for _, ok := range []string{"\u0645\u06cc\u200c\u062e\u0648\u0627\u0645", "\u0915\u094d\u200d\u0937", "Acme \U0001F468\u200d\U0001F4BB"} {
		got, err := normalizeText("name", ok, tenantNameMaxRunes)
		require.NoError(t, err, "%q", ok)
		assert.Equal(t, ok, got)
	}
	for _, bad := range []string{"Acme\u202egnp.exe", "Ac\u2066me", "Acme\u200b", "Acme\x00", "Ac\tme", "Acme\u2028Corp", "Acme\u2029Corp"} {
		_, err := normalizeText("name", bad, tenantNameMaxRunes)
		require.ErrorIs(t, err, ErrInvalidArgument, "%q", bad)
	}
}

// A tenant_id no tenant could have is refused as malformed before the
// refresh token is read, so the token still rotates; a 64-character id of
// the allowed characters is well formed.
func TestRefreshToken_MalformedTenantIDRefusedBeforeTheTokenIsRead(t *testing.T) {
	f := newSelectionFixture(t)
	ctx := context.Background()
	for name, id := range map[string]string{
		"too long":            strings.Repeat("a", maxTenantIDLen+1),
		"a space inside":      "acme corp",
		"a slash":             "acme/other",
		"non-ASCII":           "acm\u00e9",
		"a control character": "acme\x00",
	} {
		_, _, _, err := f.svc.RefreshToken(ctx, f.refresh, id, "", "")
		require.ErrorIs(t, err, ErrInvalidArgument, name)
		var refusal *TenantSelectionRefusedError
		assert.NotErrorAs(t, err, &refusal, name)
	}

	longest := strings.Repeat("a", maxTenantIDLen-2) + "-_"
	f.seedTenant(t, longest, TenantStatusClaimed, MembershipStatusActive)
	_, access, _, err := f.svc.RefreshToken(ctx, f.refresh, longest, "", "")
	require.NoError(t, err, "the refused ids left the refresh token unspent")
	assert.Equal(t, longest, f.tenantClaim(t, access))
}

// governTenant gives the fixture's project a governance plane in which the
// claimed tenant id has verified domain and, unless p is nil, the login
// policy p. It returns the policy store, for a test to fail.
func (f *selectionFixture) governTenant(id, domain string, p *LoginPolicy) *fakePolicyStore {
	project := f.project()
	policies := &fakePolicyStore{byTenant: map[string]*LoginPolicy{}}
	if p != nil {
		p.ProjectID, p.TenantID = project, id
		policies.byTenant[project+"|"+id] = p
	}
	f.svc.WithLoginGovernance(&LoginGovernance{
		Domains: &lpDomainStore{byName: map[string]*Domain{
			project + "|" + domain: {ProjectID: project, TenantID: id, Domain: domain, Status: DomainStatusVerified},
		}},
		Tenants:  &lpTenantStore{byID: map[string]*Tenant{project + "|" + id: {ID: id, ProjectID: project, Status: TenantStatusClaimed}}},
		Policies: policies,
	})
	return policies
}

// Selecting a tenant holds the session to that tenant's login policy. A
// policy that restricts sign-in admits only a session it governed, one
// whose account is on the tenant's domain, since a session does not record
// how it signed in; any policy's timeouts apply. A refusal leaves the
// refresh token unspent.
func TestRefreshToken_SelectionHeldToTheTenantsLoginPolicy(t *testing.T) {
	const memberDomain = "example.com" // the fixture's member signs up on it
	for _, tc := range []struct {
		name     string
		domain   string
		policy   *LoginPolicy
		later    time.Duration
		admitted bool
	}{
		{name: "no policy", domain: "acme.example.test", admitted: true},
		{name: "SSO required, member on another domain", domain: "acme.example.test", policy: &LoginPolicy{SSORequired: true}},
		{name: "2FA required, member on another domain", domain: "acme.example.test", policy: &LoginPolicy{Require2FA: true}},
		{name: "methods limited, member on another domain", domain: "acme.example.test", policy: &LoginPolicy{AllowedMethods: LoginMethodOAuth}},
		{name: "SSO required, member on the tenant's domain", domain: memberDomain, policy: &LoginPolicy{SSORequired: true}, admitted: true},
		{name: "timeouts only, within them", domain: "acme.example.test", policy: &LoginPolicy{SessionAbsoluteTimeoutSeconds: 3600}, admitted: true},
		{name: "timeouts only, past the absolute one", domain: "acme.example.test", policy: &LoginPolicy{SessionAbsoluteTimeoutSeconds: 60}, later: 2 * time.Minute},
		{name: "timeouts only, past the idle one", domain: "acme.example.test", policy: &LoginPolicy{SessionIdleTimeoutSeconds: 60}, later: 2 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSelectionFixture(t)
			f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusActive)
			f.governTenant("t-acme", tc.domain, tc.policy)
			if tc.later > 0 {
				later := time.Now().Add(tc.later)
				f.svc.nowFunc = func() time.Time { return later }
			}

			_, access, _, err := f.svc.RefreshToken(context.Background(), f.refresh, "t-acme", "", "")
			if tc.admitted {
				require.NoError(t, err)
				assert.Equal(t, "t-acme", f.tenantClaim(t, access))
				return
			}
			require.ErrorIs(t, err, ErrPermissionDenied)
			requireSelectionRefusal(t, err, TenantSelectionLoginPolicy)
			_, access, _, err = f.svc.RefreshToken(context.Background(), f.refresh, "", "", "")
			require.NoError(t, err, "the refused selection left the refresh token unspent")
			assert.Equal(t, f.svc.cfg.DefaultTenantID, f.tenantClaim(t, access))
		})
	}
}

// A policy that cannot be read refuses the selection as unavailable, with a
// message that does not carry the store's error, and spends nothing.
func TestRefreshToken_SelectionPolicyLookupFailureIsUnavailable(t *testing.T) {
	f := newSelectionFixture(t)
	f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusActive)
	boom := errors.New("policy store down")
	f.governTenant("t-acme", "acme.example.test", &LoginPolicy{SSORequired: true}).err = boom

	_, _, _, err := f.svc.RefreshToken(context.Background(), f.refresh, "t-acme", "", "")
	require.ErrorIs(t, err, ErrUnavailable)
	requireSelectionRefusal(t, err, TenantSelectionUnavailable)
	assert.NotErrorIs(t, err, boom)
	assert.NotContains(t, err.Error(), boom.Error())

	_, _, _, err = f.svc.RefreshToken(context.Background(), f.refresh, "", "", "")
	require.NoError(t, err)
}

// Creating a tenant needs a proven address: an unverified account is
// refused and nothing is created or audited.
func TestCreateTenant_RequiresAVerifiedEmail(t *testing.T) {
	f := newSelfServiceFixture(&config.Config{})
	f.users.set(ssProject, &User{ID: ssOwnerID, Email: "owner@example.test", Status: StatusActive})

	_, err := f.svc.CreateTenant(withTenantsProject(true), ssOwnerID, "Acme", "", "")
	require.ErrorIs(t, err, ErrEmailVerificationRequired)
	assert.Empty(t, f.tenants.byID)
	assert.Zero(t, f.audit.countByEventTypeActorTarget(string(audit.EventTenantCreated), ssOwnerID, ssOwnerID))
}
