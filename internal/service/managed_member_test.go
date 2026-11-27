package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
)

const (
	managedMemberID = "user-managed"
	managedAddress  = "ann@acme.example.com"
	managedRecovery = "ann.home@example.net"
	managedDelivery = "ann.new@example.net"
)

// fakeManagedMembers is a ManagedMemberStore whose every method the test
// programs; a method left nil fails the test when called.
type fakeManagedMembers struct {
	t       *testing.T
	suspend func(projectID, tenantID, userID, by string) (*ManagedMemberChange, error)
	remove  func(projectID, tenantID, userID, by string) (*ManagedMemberChange, error)
	reset   func(ManagedReset) (*ManagedResetDone, error)
}

func (f *fakeManagedMembers) SuspendManaged(_ context.Context, projectID, tenantID, userID, by string) (*ManagedMemberChange, error) {
	require.NotNil(f.t, f.suspend, "SuspendManaged called")
	return f.suspend(projectID, tenantID, userID, by)
}

func (f *fakeManagedMembers) RemoveManaged(_ context.Context, projectID, tenantID, userID, by string) (*ManagedMemberChange, error) {
	require.NotNil(f.t, f.remove, "RemoveManaged called")
	return f.remove(projectID, tenantID, userID, by)
}

func (f *fakeManagedMembers) ResetManaged(_ context.Context, r ManagedReset) (*ManagedResetDone, error) {
	require.NotNil(f.t, f.reset, "ResetManaged called")
	return f.reset(r)
}

// recordingInvalidator records the sessions dropped from the session cache.
type recordingInvalidator struct{ sids []string }

func (r *recordingInvalidator) Invalidate(sid string) { r.sids = append(r.sids, sid) }

type managedFixture struct {
	*selfServiceFixture
	managed  *fakeManagedMembers
	sessions *recordingInvalidator
	mailer   *recordingMailer
}

// newManagedFixture is a self-service fixture whose tenant, made by an
// operator, manages managedMemberID; the server enables managed accounts.
func newManagedFixture(t *testing.T) *managedFixture {
	t.Helper()
	f := newSelfServiceFixture(&config.Config{ManagedAccountsEnabled: true, AccountMergeReauthMaxAgeSeconds: 300})
	f.tenants.ensure(ssProject, ownTenant)
	f.users.set(ssProject, &User{
		ID: managedMemberID, Email: managedAddress, Name: "Ann", Status: StatusActive,
		EmailVerified: true, ManagedByTenantID: ownTenant, SetUpAtMs: 1, SetupEpoch: 1,
	})
	for _, m := range []*TenantMembership{
		{ProjectID: ssProject, TenantID: ownTenant, UserID: ssOwnerID, Source: MembershipSourceCreated, Role: RoleOwner, Status: MembershipStatusActive},
		{ProjectID: ssProject, TenantID: ownTenant, UserID: ssOtherID, Source: MembershipSourceInvited, Role: RoleMember, Status: MembershipStatusActive},
		{ProjectID: ssProject, TenantID: ownTenant, UserID: managedMemberID, Source: MembershipSourceInvited, Role: RoleMember, Status: MembershipStatusActive},
	} {
		_, err := f.members.UpsertMembership(context.Background(), m)
		require.NoError(t, err)
	}
	managed, sessions, mailer := &fakeManagedMembers{t: t}, &recordingInvalidator{}, &recordingMailer{}
	f.svc.WithManagedMembers(managed, sessions)
	f.svc.mailer = mailer
	return &managedFixture{selfServiceFixture: f, managed: managed, sessions: sessions, mailer: mailer}
}

// managedProject is a request in ssProject, which admits managed accounts as
// given.
func managedProject(admit, selfService bool) context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: ssProject,
		Access: ProjectAccessConfig{
			Mode: AccessModeOpen, AdmitManagedAccounts: admit, AdmitManagedAccountsSelfService: selfService,
		},
	})
}

func managedChange(status string) *ManagedMemberChange {
	return &ManagedMemberChange{
		Membership: &TenantMembership{
			ProjectID: ssProject, TenantID: ownTenant, UserID: managedMemberID,
			Source: MembershipSourceInvited, Role: RoleMember, Status: status,
		},
		Changed:             true,
		RevokedSessionIDs:   []string{"sid-1", "sid-2"},
		DeactivatedAgentIDs: []string{"agent-1"},
	}
}

// ── SuspendTenantMember / RemoveTenantMember on a managed account ────────

func TestSuspendTenantMember_ManagedAccountSignsOutEverywhere(t *testing.T) {
	f := newManagedFixture(t)
	var asked []string
	f.managed.suspend = func(projectID, tenantID, userID, by string) (*ManagedMemberChange, error) {
		asked = []string{projectID, tenantID, userID, by}
		return managedChange(MembershipStatusSuspended), nil
	}

	got, err := f.svc.SuspendTenantMember(managedProject(true, false), ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "203.0.113.7", "test-agent")
	require.NoError(t, err)
	assert.Equal(t, []string{ssProject, ownTenant, managedMemberID, ssOwnerID}, asked)
	assert.Equal(t, MembershipStatusSuspended, got.Status)
	assert.Equal(t, []string{"sid-1", "sid-2"}, f.sessions.sids, "the ended sessions leave the cache")
	assert.Equal(t, []map[string]any{{
		"project_id": ssProject, "tenant_id": ownTenant, "role": RoleMember, "source": MembershipSourceInvited,
		"status": MembershipStatusSuspended, "managed": true, "sessions_ended": float64(2),
		"agents_deactivated": []any{"agent-1"},
	}}, f.audit.detailsOf(string(audit.EventTenantMemberSuspended)))
	assert.Equal(t, MembershipStatusActive, f.membership(t, managedMemberID).Status,
		"the ordinary suspension is not used for a managed account")
}

func TestSuspendTenantMember_ManagedAccountAlreadySuspendedRecordsNothing(t *testing.T) {
	f := newManagedFixture(t)
	f.managed.suspend = func(_, _, _, _ string) (*ManagedMemberChange, error) {
		return &ManagedMemberChange{Membership: managedChange(MembershipStatusSuspended).Membership}, nil
	}

	got, err := f.svc.SuspendTenantMember(managedProject(true, false), ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "", "")
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusSuspended, got.Status)
	assert.Empty(t, f.sessions.sids)
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantMemberSuspended)))
}

func TestRemoveTenantMember_ManagedAccountIsDeactivatedAndSignedOut(t *testing.T) {
	f := newManagedFixture(t)
	var asked []string
	f.managed.remove = func(projectID, tenantID, userID, by string) (*ManagedMemberChange, error) {
		asked = []string{projectID, tenantID, userID, by}
		return managedChange(MembershipStatusActive), nil
	}

	require.NoError(t, f.svc.RemoveTenantMember(managedProject(true, false), ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "203.0.113.7", "test-agent"))
	assert.Equal(t, []string{ssProject, ownTenant, managedMemberID, ssOwnerID}, asked)
	assert.Equal(t, []string{"sid-1", "sid-2"}, f.sessions.sids)
	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(string(audit.EventTenantMemberRemoved), ssOwnerID, managedMemberID))
	assert.Equal(t, true, f.audit.detailsOf(string(audit.EventTenantMemberRemoved))[0]["managed"])
}

func TestRemoveTenantMember_ManagedAccountWithNoMembershipIsANoOp(t *testing.T) {
	f := newManagedFixture(t)
	f.managed.remove = func(_, _, _, _ string) (*ManagedMemberChange, error) {
		return nil, ErrNotFound
	}

	require.NoError(t, f.svc.RemoveTenantMember(managedProject(true, false), ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "", ""))
	assert.Empty(t, f.sessions.sids)
	assert.Zero(t, f.audit.countByEventType(string(audit.EventTenantMemberRemoved)))
}

func TestRemoveTenantMember_ManagedAccountCannotLeave(t *testing.T) {
	f := newManagedFixture(t)
	_, err := f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: ssProject, TenantID: ownTenant, UserID: managedMemberID,
		Source: MembershipSourceInvited, Role: RoleAdmin, Status: MembershipStatusActive,
	})
	require.NoError(t, err)

	sessions := newFakeRepo()
	f.svc.WithAccounts(sessions)
	err = f.svc.RemoveTenantMember(managedProject(true, false), managedMemberID, liveSession(t, sessions, managedMemberID), ownTenant, managedMemberID, "", "")
	require.ErrorIs(t, err, ErrManagedAccount)
	assert.Equal(t, MembershipStatusActive, f.membership(t, managedMemberID).Status)
}

func TestManagedMemberChanges_StoreErrorsPassThrough(t *testing.T) {
	f := newManagedFixture(t)
	f.managed.suspend = func(_, _, _, _ string) (*ManagedMemberChange, error) { return nil, ErrLastOwner }
	f.managed.remove = func(_, _, _, _ string) (*ManagedMemberChange, error) { return nil, ErrPermissionDenied }
	ctx := managedProject(true, false)

	_, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "", "")
	require.ErrorIs(t, err, ErrLastOwner)
	require.ErrorIs(t, f.svc.RemoveTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "", ""), ErrPermissionDenied)
	assert.Empty(t, f.sessions.sids)
}

// A personal account, or one another tenant manages, takes the ordinary
// path; the managed store is never asked.
func TestManagedMemberChanges_OtherAccountsTakeTheOrdinaryPath(t *testing.T) {
	for name, user := range map[string]*User{
		"personal":                  {ID: ssOtherID, Email: "other@example.test", Status: StatusActive, EmailVerified: true},
		"managed by another tenant": {ID: ssOtherID, Email: "bo@other.example.com", Status: StatusActive, EmailVerified: true, ManagedByTenantID: "t-other"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newManagedFixture(t)
			f.users.set(ssProject, user)
			ctx := managedProject(true, false)

			got, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, ssOtherID, "", "")
			require.NoError(t, err)
			assert.Equal(t, MembershipStatusSuspended, got.Status)
			require.NoError(t, f.svc.RemoveTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, ssOtherID, "", ""))
			m, err := f.members.GetMembership(context.Background(), ssProject, ownTenant, ssOtherID)
			require.NoError(t, err)
			assert.Nil(t, m)
			assert.Empty(t, f.sessions.sids)
		})
	}
}

func TestManagedMemberChanges_RefusedWithoutAManagedStore(t *testing.T) {
	f := newManagedFixture(t)
	f.svc.WithManagedMembers(nil, nil)
	ctx := managedProject(true, false)

	_, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "", "")
	require.ErrorIs(t, err, ErrServiceUnavailable)
	require.ErrorIs(t, f.svc.RemoveTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "", ""), ErrServiceUnavailable)
	assert.Equal(t, MembershipStatusActive, f.membership(t, managedMemberID).Status)
}

// ── ResetManagedAccount ──────────────────────────────────────────────────

func freshSignIn() SessionSignIn {
	return SessionSignIn{AuthTimeSec: time.Now().Unix(), SessionID: "sid-caller"}
}

func (f *managedFixture) programReset(t *testing.T, got *ManagedReset) {
	t.Helper()
	f.programResetOf(t, got, RoleMember)
}

// programResetOf answers a reset as the store does for a member with role.
func (f *managedFixture) programResetOf(t *testing.T, got *ManagedReset, role string) {
	t.Helper()
	f.managed.reset = func(r ManagedReset) (*ManagedResetDone, error) {
		*got = r
		return &ManagedResetDone{
			User: &User{ID: managedMemberID, Email: managedAddress, Name: "Ann", Status: StatusInvited, ManagedByTenantID: ownTenant},
			Invitation: &TenantInvitation{
				ID: "inv-1", ProjectID: ssProject, TenantID: ownTenant, Email: managedAddress, InvitedBy: r.By,
				Role: role, Status: InvitationStatusPending, ExpiresAtMs: r.ExpiresAtMs, TokenHash: r.TokenHash,
				TokenOnlyInEmail: true, UserID: managedMemberID, DeliveryEmail: r.DeliveryEmail, SetupEpoch: 2,
			},
			NoticeEmails:        []string{managedAddress, managedRecovery},
			RevokedSessionIDs:   []string{"sid-1"},
			DeactivatedAgentIDs: []string{"agent-1"},
		}, nil
	}
}

func TestResetManagedAccount_ResetsNotifiesAndSendsTheSetUpLink(t *testing.T) {
	f := newManagedFixture(t)
	var asked ManagedReset
	f.programReset(t, &asked)

	out, err := f.svc.ResetManagedAccount(managedProject(true, false), ssOwnerID, freshSignIn(), " "+ownTenant+" ", " "+managedMemberID+" ", " Ann.New@Example.net ", "203.0.113.7", "test-agent")
	require.NoError(t, err)

	cfg := f.svc.config()
	assert.Equal(t, ssProject, asked.ProjectID)
	assert.Equal(t, ownTenant, asked.TenantID)
	assert.Equal(t, managedMemberID, asked.UserID)
	assert.Equal(t, ssOwnerID, asked.By)
	assert.Equal(t, managedDelivery, asked.DeliveryEmail, "the delivery address is canonical")
	assert.NotEmpty(t, asked.TokenHash)
	assert.Equal(t, cfg.TenantInvitationLimit(), asked.Limits.MaxPerTenant)
	assert.Equal(t, cfg.TenantInvitationInviterLimit(), asked.Limits.MaxPerInviter)
	assert.Equal(t, cfg.TenantInvitationRecipientLimit(), asked.MaxPerDeliveryEmail)
	assert.InDelta(t, time.Now().Add(defaultInvitationTTL).UnixMilli(), asked.ExpiresAtMs, float64(time.Minute.Milliseconds()))

	assert.Equal(t, EmailSent, out.EmailStatus)
	assert.Equal(t, "inv-1", out.Invitation.ID)
	assert.Equal(t, []string{"sid-1"}, f.sessions.sids)

	require.Equal(t, 3, f.mailer.count())
	var to []string
	for _, m := range f.mailer.sent {
		to = append(to, m.To)
	}
	assert.Equal(t, []string{managedAddress, managedRecovery, managedDelivery}, to, "the notices go first, then the link")
	assert.Contains(t, f.mailer.sent[0].Text, "contact your organization's administrator")
	assert.Contains(t, f.mailer.sent[0].Text, "Hi Ann,", "an operator's tenant greets by the account's name")
	assert.Contains(t, f.mailer.last().Text, "token=")
	assert.Equal(t, asked.TokenHash, sha256Hex(extractTokenFromLink(t, f.mailer.last().Text)))

	assert.Equal(t, 1, f.audit.countByEventTypeActorTarget(string(audit.EventManagedAccountReset), ssOwnerID, managedMemberID))
	assert.Equal(t, []map[string]any{{
		"project_id": ssProject, "tenant_id": ownTenant, "role": RoleMember,
		"delivery_email": redactEmail(managedDelivery), "sessions_ended": float64(1),
		"agents_deactivated": []any{"agent-1"}, "review": managedResetReviewNote,
		"owners_notice_due": false,
	}}, f.audit.detailsOf(string(audit.EventManagedAccountReset)))
	assert.Equal(t, [][2]string{{"203.0.113.7", "test-agent"}}, f.audit.clientsOf(string(audit.EventManagedAccountReset)))
}

func TestResetManagedAccount_AFailedLinkSendDoesNotFailTheReset(t *testing.T) {
	f := newManagedFixture(t)
	var asked ManagedReset
	f.programReset(t, &asked)
	f.mailer.sendErr = errors.New("smtp down")

	out, err := f.svc.ResetManagedAccount(managedProject(true, false), ssOwnerID, freshSignIn(), ownTenant, managedMemberID, managedDelivery, "", "")
	require.NoError(t, err)
	assert.Equal(t, EmailSendFailed, out.EmailStatus)
	assert.Equal(t, 1, f.audit.countByEventType(string(audit.EventManagedAccountReset)))
}

func TestResetManagedAccount_Refusals(t *testing.T) {
	stale := SessionSignIn{AuthTimeSec: time.Now().Add(-time.Hour).Unix(), SessionID: "sid-caller"}
	held := SessionSignIn{AuthTimeSec: time.Now().Unix(), AMR: []string{AMRRecoveryEmail}, RecoveryEmailID: "re-1"}
	for name, tc := range map[string]struct {
		mutate func(*managedFixture)
		ctx    context.Context
		caller string
		signIn SessionSignIn
		tenant string
		user   string
		to     string
		want   error
	}{
		"flag off": {
			mutate: func(f *managedFixture) { f.svc.cfg.ManagedAccountsEnabled = false },
			want:   ErrManagedAccountsNotAdmitted,
		},
		"project does not admit": {ctx: managedProject(false, false), want: ErrManagedAccountsNotAdmitted},
		"no project scope":       {ctx: context.Background(), want: ErrPermissionDenied},
		"self-service tenant without its admission": {
			mutate: func(f *managedFixture) { f.tenants.byID[ssProject+"/"+ownTenant].CreatedBy = ssOwnerID },
			want:   ErrManagedAccountsNotAdmitted,
		},
		"unauthenticated":        {caller: "-", want: ErrUnauthenticated},
		"stale sign-in":          {signIn: stale, want: ErrManagedResetReauthenticationRequired},
		"no sign-in time":        {signIn: SessionSignIn{SessionID: "sid-caller"}, want: ErrManagedResetReauthenticationRequired},
		"recovery-email session": {signIn: held, want: ErrServiceUnavailable},
		"own account":            {user: ssOwnerID, want: ErrInvalidArgument},
		"no tenant":              {tenant: "-", want: ErrInvalidArgument},
		"no user":                {user: "-", want: ErrInvalidArgument},
		"bad delivery address":   {to: "not-an-address", want: ErrInvalidArgument},
		"not an admin":           {caller: ssOtherID, want: ErrPermissionDenied},
		"tenant suspended": {
			mutate: func(f *managedFixture) { f.tenants.byID[ssProject+"/"+ownTenant].Status = TenantStatusSuspended },
			want:   ErrPermissionDenied,
		},
		"no mailer": {
			mutate: func(f *managedFixture) { f.svc.mailerDelivers = false },
			want:   ErrManagedSetupNeedsMailer,
		},
		"no managed store": {
			mutate: func(f *managedFixture) { f.svc.WithManagedMembers(nil, nil) },
			want:   ErrUnimplemented,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newManagedFixture(t)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			ctx := tc.ctx
			if ctx == nil {
				ctx = managedProject(true, false)
			}
			pick := func(v, def string) string {
				switch v {
				case "":
					return def
				case "-":
					return ""
				}
				return v
			}
			signIn := tc.signIn
			if signIn.AuthTimeSec == 0 && signIn.SessionID == "" {
				signIn = freshSignIn()
			}
			_, err := f.svc.ResetManagedAccount(ctx, pick(tc.caller, ssOwnerID), signIn,
				pick(tc.tenant, ownTenant), pick(tc.user, managedMemberID), pick(tc.to, managedDelivery), "", "")
			require.ErrorIs(t, err, tc.want)
			assert.Zero(t, f.mailer.count())
			assert.Zero(t, f.audit.countByEventType(string(audit.EventManagedAccountReset)))
		})
	}
}

func TestResetManagedAccount_SelfServiceTenantAdmittedByItsOwnSwitch(t *testing.T) {
	f := newManagedFixture(t)
	f.tenants.byID[ssProject+"/"+ownTenant].CreatedBy = ssOwnerID
	var asked ManagedReset
	f.programReset(t, &asked)

	_, err := f.svc.ResetManagedAccount(managedProject(true, true), ssOwnerID, freshSignIn(), ownTenant, managedMemberID, managedDelivery, "", "")
	require.NoError(t, err)
	assert.Equal(t, managedMemberID, asked.UserID)
	require.Equal(t, 3, f.mailer.count())
	for _, m := range f.mailer.sent {
		assert.Contains(t, m.Text, "Hi ann,", "a self-service tenant's typed name is not used: the notices and the link greet by the address")
		assert.NotContains(t, m.Text, "Hi Ann,")
	}
}

// managedAccountGreeting uses the typed name only for an operator's tenant.
func TestManagedAccountGreeting(t *testing.T) {
	ann := &User{Email: "ann@acme.example.com", Name: "Ann"}
	greeting, tenant := managedAccountGreeting(&Tenant{Name: "Acme"}, ann)
	assert.Equal(t, [2]string{"Ann", "Acme"}, [2]string{greeting, tenant})
	greeting, tenant = managedAccountGreeting(&Tenant{Name: "Acme", CreatedBy: "u-owner"}, ann)
	assert.Equal(t, [2]string{"ann", ""}, [2]string{greeting, tenant})
	greeting, tenant = managedAccountGreeting(nil, ann)
	assert.Equal(t, [2]string{"ann", ""}, [2]string{greeting, tenant})
}

func TestResetManagedAccount_StoreRefusalsPassThrough(t *testing.T) {
	for _, want := range []error{ErrNotFound, ErrPermissionDenied, ErrManagedResetLimited, ErrInvitationLimited, ErrInviterLimited, errors.New("boom")} {
		f := newManagedFixture(t)
		f.managed.reset = func(ManagedReset) (*ManagedResetDone, error) { return nil, want }

		_, err := f.svc.ResetManagedAccount(managedProject(true, false), ssOwnerID, freshSignIn(), ownTenant, managedMemberID, managedDelivery, "", "")
		require.ErrorIs(t, err, want)
		assert.Zero(t, f.mailer.count())
		assert.Empty(t, f.sessions.sids)
	}
}

func TestSignedInWithin(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	for authTime, want := range map[int64]bool{
		0:                                 false,
		now.Unix():                        true,
		now.Unix() - 300:                  true,
		now.Unix() - 301:                  false,
		now.Unix() + 30:                   true,
		now.Unix() + 31:                   false,
		now.Unix() - int64(time.Hour/1e9): false,
	} {
		assert.Equal(t, want, signedInWithin(now, authTime, 5*time.Minute), "auth_time %d", authTime)
	}
}

func (f *managedFixture) membership(t *testing.T, userID string) *TenantMembership {
	t.Helper()
	m, err := f.members.GetMembership(context.Background(), ssProject, ownTenant, userID)
	require.NoError(t, err)
	require.NotNil(t, m, userID)
	return m
}

// An admin resetting another admin's managed account is told to every active
// owner of the tenant; an owner's reset of an admin, and an admin's reset of
// a member, tell no owner.
func TestResetManagedAccount_AdminResettingAnAdminTellsTheOwners(t *testing.T) {
	for name, tc := range map[string]struct {
		caller, callerRole, targetRole string
		ownersTold                     int
	}{
		"admin resets admin":  {caller: ssOtherID, callerRole: RoleAdmin, targetRole: RoleAdmin, ownersTold: 1},
		"owner resets admin":  {caller: ssOwnerID, callerRole: RoleOwner, targetRole: RoleAdmin},
		"admin resets member": {caller: ssOtherID, callerRole: RoleAdmin, targetRole: RoleMember},
	} {
		t.Run(name, func(t *testing.T) {
			f := newManagedFixture(t)
			if tc.caller == ssOtherID {
				_, err := f.members.UpsertMembership(context.Background(), &TenantMembership{
					ProjectID: ssProject, TenantID: ownTenant, UserID: ssOtherID,
					Source: MembershipSourceInvited, Role: tc.callerRole, Status: MembershipStatusActive,
				})
				require.NoError(t, err)
			}
			_, err := f.members.UpsertMembership(context.Background(), &TenantMembership{
				ProjectID: ssProject, TenantID: ownTenant, UserID: "user-owner-away",
				Source: MembershipSourceInvited, Role: RoleOwner, Status: MembershipStatusSuspended,
			})
			require.NoError(t, err)
			accounts := newFakeRepo()
			accounts.mu.Lock()
			accounts.users[ssOwnerID] = &User{ID: ssOwnerID, Email: "owner@example.test", Name: "Olive", Status: StatusActive}
			accounts.users["user-owner-away"] = &User{ID: "user-owner-away", Email: "away@example.test", Status: StatusActive}
			accounts.mu.Unlock()
			f.svc.WithAccounts(accounts)
			var asked ManagedReset
			f.programResetOf(t, &asked, tc.targetRole)

			_, err = f.svc.ResetManagedAccount(managedProject(true, false), tc.caller, freshSignIn(), ownTenant, managedMemberID, managedDelivery, "", "")
			require.NoError(t, err)

			var told []string
			for _, m := range f.mailer.sent {
				if m.Subject == "An admin reset another admin's sign-in" {
					told = append(told, m.To)
					assert.Contains(t, m.Text, "other@example.test reset "+managedAddress+"'s sign-in", "the admin is named by address only")
					assert.Contains(t, m.Text, "Hi Olive,")
				}
			}
			if tc.ownersTold == 0 {
				assert.Empty(t, told)
			} else {
				assert.Equal(t, []string{"owner@example.test"}, told, "the active owner only")
			}
			assert.Equal(t, tc.ownersTold > 0, f.audit.detailsOf(string(audit.EventManagedAccountReset))[0]["owners_notice_due"])
			notified := f.audit.detailsOf(string(audit.EventManagedAccountResetOwnersNotified))
			if tc.ownersTold == 0 {
				assert.Empty(t, notified)
				return
			}
			require.Len(t, notified, 1)
			assert.Equal(t, float64(1), notified[0]["owners"])
			assert.Equal(t, float64(1), notified[0]["owners_notified"], "the sends that succeeded")
		})
	}
}

// A failed send to an owner is not counted as notified.
func TestResetManagedAccount_OwnersNotifiedCountsSuccessfulSends(t *testing.T) {
	f := newManagedFixture(t)
	_, err := f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: ssProject, TenantID: ownTenant, UserID: ssOtherID,
		Source: MembershipSourceInvited, Role: RoleAdmin, Status: MembershipStatusActive,
	})
	require.NoError(t, err)
	accounts := newFakeRepo()
	accounts.mu.Lock()
	accounts.users[ssOwnerID] = &User{ID: ssOwnerID, Email: "owner@example.test", Status: StatusActive}
	accounts.mu.Unlock()
	f.svc.WithAccounts(accounts)
	var asked ManagedReset
	f.programResetOf(t, &asked, RoleAdmin)
	f.mailer.sendErr = errors.New("smtp down")

	_, err = f.svc.ResetManagedAccount(managedProject(true, false), ssOtherID, freshSignIn(), ownTenant, managedMemberID, managedDelivery, "", "")
	require.NoError(t, err)
	notified := f.audit.detailsOf(string(audit.EventManagedAccountResetOwnersNotified))
	require.Len(t, notified, 1)
	assert.Equal(t, float64(1), notified[0]["owners"])
	assert.Equal(t, float64(0), notified[0]["owners_notified"])
}

// The reset's notices run through the notice dispatcher, the set-up link
// does not: its send status is the call's answer.
func TestResetManagedAccount_NoticesAreDispatchedTheLinkIsNot(t *testing.T) {
	f := newManagedFixture(t)
	var asked ManagedReset
	f.programReset(t, &asked)
	dispatcher := &heldDispatcher{}
	f.svc.WithNoticeDispatch(dispatcher)

	out, err := f.svc.ResetManagedAccount(managedProject(true, false), ssOwnerID, freshSignIn(), ownTenant, managedMemberID, managedDelivery, "", "")
	require.NoError(t, err)
	assert.Equal(t, EmailSent, out.EmailStatus)
	require.Equal(t, 1, f.mailer.count(), "only the link is sent on the request path")
	assert.Equal(t, managedDelivery, f.mailer.last().To)
	assert.Equal(t, []string{"managed_account_reset_notice"}, dispatcher.ops)

	dispatcher.run()
	assert.Equal(t, 3, f.mailer.count(), "the held notices go out when the dispatcher runs them")
}

// heldDispatcher holds what it is given until run.
type heldDispatcher struct {
	ops   []string
	sends []func(context.Context)
}

func (d *heldDispatcher) dispatchEmailSend(_ context.Context, op string, send func(context.Context)) {
	d.ops = append(d.ops, op)
	d.sends = append(d.sends, send)
}

func (d *heldDispatcher) run() {
	for _, send := range d.sends {
		send(context.Background())
	}
}

// Where managed accounts are switched off, suspending or removing an account
// that is still managed acts on the account all the same: its sessions end
// at once.
func TestManagedMemberChanges_SwitchedOffStillSignOutAManagedAccount(t *testing.T) {
	f := newManagedFixture(t)
	f.svc.cfg.ManagedAccountsEnabled = false
	f.managed.suspend = func(_, _, _, _ string) (*ManagedMemberChange, error) {
		return managedChange(MembershipStatusSuspended), nil
	}
	f.managed.remove = func(_, _, _, _ string) (*ManagedMemberChange, error) {
		return managedChange(MembershipStatusSuspended), nil
	}
	ctx := managedProject(false, false)

	got, err := f.svc.SuspendTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "", "")
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusSuspended, got.Status)
	assert.Equal(t, []string{"sid-1", "sid-2"}, f.sessions.sids, "the suspension ended its sessions")
	require.NoError(t, f.svc.RemoveTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "", ""))
	assert.Equal(t, []string{"sid-1", "sid-2", "sid-1", "sid-2"}, f.sessions.sids, "so did the removal")
}

// A delivery address that is not usable is refused without echoing it.
func TestResetManagedAccount_BadDeliveryAddressIsNotEchoed(t *testing.T) {
	f := newManagedFixture(t)
	_, err := f.svc.ResetManagedAccount(managedProject(true, false), ssOwnerID, freshSignIn(), ownTenant, managedMemberID, "not-an-address@", "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)
	assert.NotContains(t, err.Error(), "not-an-address")
}

// Each argument refusal is logged as managed_account_reset_refused with its
// reason, and an unusable delivery address only redacted.
func TestResetManagedAccount_InvalidArgumentsAreLogged(t *testing.T) {
	f := newManagedFixture(t)
	core, logs := observer.New(zap.InfoLevel)
	f.svc.logger = zap.New(core)
	for _, tc := range []struct {
		name, userID, delivery, reason string
	}{
		{"no user", " ", managedDelivery, "invalid_argument"},
		{"own account", ssOwnerID, managedDelivery, "own_account"},
		{"unusable delivery address", managedMemberID, "not-an-address@", "invalid_argument"},
	} {
		logs.TakeAll()
		_, err := f.svc.ResetManagedAccount(managedProject(true, false), ssOwnerID, freshSignIn(), ownTenant, tc.userID, tc.delivery, "", "")
		require.ErrorIs(t, err, ErrInvalidArgument, tc.name)
		lines := logs.FilterMessage("managed_account_reset_refused").AllUntimed()
		require.Len(t, lines, 1, tc.name)
		fields := lines[0].ContextMap()
		assert.Equal(t, tc.reason, fields["reason"], tc.name)
		assert.Equal(t, ownTenant, fields["tenant_id"], tc.name)
		for _, l := range logs.All() {
			for _, v := range l.ContextMap() {
				assert.NotEqual(t, "not-an-address@", v, "%s: the raw address is never logged", tc.name)
			}
		}
		if tc.delivery == "not-an-address@" {
			assert.Equal(t, redactEmail(tc.delivery), fields["to"])
		}
	}
}

// Restoring a managed account says how many of its agents stay
// deactivated, in the result, the log and the audit entry; a personal
// member's restore reads no agents and its audit entry is as before.
func TestRestoreTenantMember_ManagedAccountReportsItsAgentsLeftOff(t *testing.T) {
	f := newManagedFixture(t)
	repo := newFakeRepo()
	f.svc.WithAccounts(repo)
	for _, status := range []string{StatusDeactivated, StatusDeactivated, StatusActive} {
		a := seedAgent(repo, managedMemberID)
		repo.mu.Lock()
		repo.users[a.ID].Status = status
		repo.mu.Unlock()
	}
	ctx := managedProject(true, false)
	for _, id := range []string{managedMemberID, ssOtherID} {
		_, err := f.members.UpsertMembership(context.Background(), &TenantMembership{
			ProjectID: ssProject, TenantID: ownTenant, UserID: id,
			Source: MembershipSourceInvited, Role: RoleMember, Status: MembershipStatusSuspended,
		})
		require.NoError(t, err)
	}

	got, err := f.svc.RestoreTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "", "")
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusActive, got.Membership.Status)
	assert.Equal(t, 2, got.AgentsLeftDeactivated)
	details := f.audit.detailsOf(string(audit.EventTenantMemberRestored))
	require.Len(t, details, 1)
	assert.Equal(t, true, details[0]["managed"])
	assert.Equal(t, float64(2), details[0]["agents_left_deactivated"])

	personal, err := f.svc.RestoreTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, ssOtherID, "", "")
	require.NoError(t, err)
	assert.Zero(t, personal.AgentsLeftDeactivated)
	details = f.audit.detailsOf(string(audit.EventTenantMemberRestored))
	require.Len(t, details, 2)
	assert.NotContains(t, details[1], "agents_left_deactivated")

	f.svc.WithAccounts(nil)
	_, err = f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: ssProject, TenantID: ownTenant, UserID: managedMemberID,
		Source: MembershipSourceInvited, Role: RoleMember, Status: MembershipStatusSuspended,
	})
	require.NoError(t, err)
	_, err = f.svc.RestoreTenantMember(ctx, ssOwnerID, SessionSignIn{}, ownTenant, managedMemberID, "", "")
	require.ErrorIs(t, err, ErrServiceUnavailable, "a managed account's agents that cannot be read refuse the restore before it writes")
	assert.Equal(t, MembershipStatusSuspended, f.membership(t, managedMemberID).Status)
}
