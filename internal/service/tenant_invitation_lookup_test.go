package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
)

var lookupNow = time.UnixMilli(1_800_000_000_000)

// invitationLookupFixture is a MembershipService over an operator's tenant,
// "Acme", whose owner mAdminID ("Maya Chen") sends the invitations, with an
// account store to answer whether the invited address has an account.
type invitationLookupFixture struct {
	*membershipFixture
	accounts *fakeRepo
}

func newInvitationLookupFixture(mailerDelivers bool) *invitationLookupFixture {
	f := newMembershipFixtureWith(mailerDelivers, &config.Config{})
	f.svc.nowFunc = func() time.Time { return lookupNow }
	accounts := newFakeRepo()
	f.svc.WithAccounts(accounts)
	f.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Name: "Acme", Status: TenantStatusClaimed})
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	f.users.set(mTestProject, &User{ID: mAdminID, Name: "Maya Chen", Email: "maya@acme.com", EmailVerified: true})
	return &invitationLookupFixture{membershipFixture: f, accounts: accounts}
}

// seed stores an invitation of mTestProject's tenant to mInvitee, from
// mAdminID, in status, expiring expiresIn from lookupNow, whose token went
// only into its email, and returns the raw token that email would carry.
func (f *invitationLookupFixture) seed(id, status string, expiresIn time.Duration) string {
	return f.seedIn(mTestProject, id, status, expiresIn)
}

func (f *invitationLookupFixture) seedIn(projectID, id, status string, expiresIn time.Duration) string {
	raw := randomToken(invitationTokenBytes)
	f.invitations.byID[f.invitations.key(projectID, id)] = &TenantInvitation{
		ID: id, ProjectID: projectID, TenantID: mTestTenant, TokenHash: sha256Hex(raw),
		Email: mInvitee, InvitedBy: mAdminID, Role: RoleAdmin, Status: status,
		ExpiresAtMs: lookupNow.Add(expiresIn).UnixMilli(), CreatedAtMs: lookupNow.Add(-time.Hour).UnixMilli(),
		TokenOnlyInEmail: true,
	}
	return raw
}

// snapshot copies every stored invitation, to show a call left them as they
// were.
func (f *invitationLookupFixture) snapshot() map[string]TenantInvitation {
	out := make(map[string]TenantInvitation, len(f.invitations.byID))
	for k, inv := range f.invitations.byID {
		out[k] = *inv
	}
	return out
}

func TestGetTenantInvitation_DescribesAPendingInvitation(t *testing.T) {
	f := newInvitationLookupFixture(true)
	token := f.seed("inv-1", InvitationStatusPending, 24*time.Hour)

	view, err := f.svc.GetTenantInvitation(withProject(mTestProject), "  "+token+" ")
	require.NoError(t, err)
	require.Equal(t, &TenantInvitationView{
		TenantID:      mTestTenant,
		TenantName:    "Acme",
		InviterName:   "Maya Chen",
		InviterEmail:  "maya@acme.com",
		Email:         mInvitee,
		Role:          RoleAdmin,
		ExpiresAtMs:   lookupNow.Add(24 * time.Hour).UnixMilli(),
		Status:        InvitationStatusPending,
		AccountExists: false,
	}, view)
}

// Each status reads as stored, except a pending invitation past its expiry,
// which reads expired without being marked so.
func TestGetTenantInvitation_ReportsEachStatusAndChangesNothing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    string
		expiresIn time.Duration
		want      string
	}{
		{"pending", InvitationStatusPending, time.Hour, InvitationStatusPending},
		{"pending_past_expiry", InvitationStatusPending, -time.Minute, InvitationStatusExpired},
		{"expired_recorded", InvitationStatusExpired, -time.Minute, InvitationStatusExpired},
		{"accepted", InvitationStatusAccepted, time.Hour, InvitationStatusAccepted},
		{"revoked", InvitationStatusRevoked, time.Hour, InvitationStatusRevoked},
		{"accepted_past_expiry", InvitationStatusAccepted, -time.Minute, InvitationStatusAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInvitationLookupFixture(true)
			token := f.seed("inv-1", tc.status, tc.expiresIn)
			before := f.snapshot()

			view, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
			require.NoError(t, err)
			require.Equal(t, tc.want, view.Status)
			require.Equal(t, "Maya Chen", view.InviterName, "a closed invitation still names who to ask for a new one")
			require.Equal(t, before, f.snapshot(), "reading an invitation writes nothing")
			require.Zero(t, f.mailer.count())
		})
	}
}

// Reading does not use the token up: the invitee accepts it afterwards.
func TestGetTenantInvitation_LeavesTheTokenRedeemable(t *testing.T) {
	f := newInvitationLookupFixture(true)
	token := f.seed("inv-1", InvitationStatusPending, time.Hour)
	f.users.put(mTestProject, mInviteeID, mInvitee)
	ctx := withProject(mTestProject)

	for range 3 {
		_, err := f.svc.GetTenantInvitation(ctx, token)
		require.NoError(t, err)
	}
	m, err := f.svc.AcceptTenantInvitation(ctx, mInviteeID, token)
	require.NoError(t, err)
	require.Equal(t, mTestTenant, m.TenantID)

	view, err := f.svc.GetTenantInvitation(ctx, token)
	require.NoError(t, err)
	require.Equal(t, InvitationStatusAccepted, view.Status)
}

// A token no invitation of the request's project has is refused the same way
// whether it is unknown or another project's, so it tells a caller without a
// real token nothing.
func TestGetTenantInvitation_UnknownTokenIsNotFound(t *testing.T) {
	f := newInvitationLookupFixture(true)
	f.seed("inv-1", InvitationStatusPending, time.Hour)
	otherProjects := f.seedIn("proj-2", "inv-2", InvitationStatusPending, time.Hour)
	ctx := withProject(mTestProject)

	_, unknownErr := f.svc.GetTenantInvitation(ctx, randomToken(invitationTokenBytes))
	require.ErrorIs(t, unknownErr, ErrNotFound)
	_, foreignErr := f.svc.GetTenantInvitation(ctx, otherProjects)
	require.ErrorIs(t, foreignErr, ErrNotFound)
	require.Equal(t, unknownErr.Error(), foreignErr.Error())

	_, err := f.svc.GetTenantInvitation(ctx, "   ")
	require.ErrorIs(t, err, ErrInvalidArgument)
}

// An account holds the invited address as its email or as a recovery email;
// either way no account can be made on it, so either reads as existing.
func TestGetTenantInvitation_AccountExists(t *testing.T) {
	for _, tc := range []struct {
		name    string
		account func(context.Context, *fakeRepo) error
		want    bool
	}{
		{"no_account", func(_ context.Context, r *fakeRepo) error {
			seedUser(r, "someone-else@acme.com", "", StatusActive)
			return nil
		}, false},
		{"account_email", func(_ context.Context, r *fakeRepo) error {
			seedUser(r, mInvitee, "", StatusActive)
			return nil
		}, true},
		{"recovery_email", func(ctx context.Context, r *fakeRepo) error {
			holder := seedUser(r, "holder@example.com", "", StatusActive)
			return r.AddRecoveryEmail(ctx, &RecoveryEmail{UserID: holder.ID, Email: mInvitee}, 5)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInvitationLookupFixture(true)
			token := f.seed("inv-1", InvitationStatusPending, time.Hour)
			ctx := withProject(mTestProject)
			require.NoError(t, tc.account(ctx, f.accounts))

			view, err := f.svc.GetTenantInvitation(ctx, token)
			require.NoError(t, err)
			require.Equal(t, tc.want, view.AccountExists)
		})
	}
}

// Without a mailer the inviter was handed the token, so the answer would tell
// them whether any address they invite has an account: it is never given.
func TestGetTenantInvitation_AccountExistsUnansweredWithoutAMailer(t *testing.T) {
	f := newInvitationLookupFixture(false)
	token := f.seed("inv-1", InvitationStatusPending, time.Hour)
	seedUser(f.accounts, mInvitee, "", StatusActive)

	view, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
	require.NoError(t, err)
	require.False(t, view.AccountExists)
	require.Equal(t, mInvitee, view.Email, "the rest of the invitation is still described")
}

// An invitation whose token did not go only into its email, handed to the
// inviter by a server without mail or stored before that was recorded, does
// not say whether the address has an account, though the mailer delivers
// now.
func TestGetTenantInvitation_AccountExistsUnansweredForATokenThatLeftTheEmail(t *testing.T) {
	f := newInvitationLookupFixture(true)
	token := f.seed("inv-1", InvitationStatusPending, time.Hour)
	f.invitations.byID[f.invitations.key(mTestProject, "inv-1")].TokenOnlyInEmail = false
	seedUser(f.accounts, mInvitee, "", StatusActive)

	view, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
	require.NoError(t, err)
	require.False(t, view.AccountExists)
	require.Equal(t, mInvitee, view.Email, "the rest of the invitation is still described")
	require.Equal(t, InvitationStatusPending, view.Status)
}

// The tenant is named as the invitation email names it: a self-service
// tenant's typed name never appears, and a tenant with no name is named by
// its primary domain.
func TestGetTenantInvitation_TenantNameAsTheEmailShowsIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tenant Tenant
		want   string
	}{
		{"operator_tenant", Tenant{Name: "Acme"}, "Acme"},
		{"self_service_tenant", Tenant{Name: "Payroll update: sign in at payroll.example.com", CreatedBy: mAdminID}, ""},
		{"primary_domain", Tenant{PrimaryDomain: "acme.com"}, "acme.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInvitationLookupFixture(true)
			tenant := tc.tenant
			tenant.ID, tenant.ProjectID, tenant.Status = mTestTenant, mTestProject, TenantStatusClaimed
			f.tenants.put(&tenant)
			token := f.seed("inv-1", InvitationStatusPending, time.Hour)

			view, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
			require.NoError(t, err)
			require.Equal(t, tc.want, view.TenantName)
		})
	}
}

func TestGetTenantInvitation_InviterWhoNoLongerExists(t *testing.T) {
	f := newInvitationLookupFixture(true)
	token := f.seed("inv-1", InvitationStatusPending, time.Hour)
	delete(f.users.byID, f.users.key(mTestProject, mAdminID))

	view, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
	require.NoError(t, err)
	require.Empty(t, view.InviterName)
	require.Empty(t, view.InviterEmail)
}

func TestGetTenantInvitation_LookupFailuresAreReturned(t *testing.T) {
	boom := errors.New("database unavailable")
	for name, fail := range map[string]func(*invitationLookupFixture){
		"invitation": func(f *invitationLookupFixture) { f.invitations.getErr = boom },
		"tenant":     func(f *invitationLookupFixture) { f.tenants.getErr = boom },
		"inviter":    func(f *invitationLookupFixture) { f.users.getErr = boom },
	} {
		t.Run(name, func(t *testing.T) {
			f := newInvitationLookupFixture(true)
			token := f.seed("inv-1", InvitationStatusPending, time.Hour)
			fail(f)

			_, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
			require.ErrorIs(t, err, boom)
		})
	}
}

func TestGetTenantInvitation_NeedsAProjectAndAnAccountStore(t *testing.T) {
	f := newInvitationLookupFixture(true)
	token := f.seed("inv-1", InvitationStatusPending, time.Hour)

	_, err := f.svc.GetTenantInvitation(context.Background(), token)
	require.ErrorIs(t, err, ErrPermissionDenied)

	f.svc.accounts = nil
	_, err = f.svc.GetTenantInvitation(withProject(mTestProject), token)
	require.ErrorIs(t, err, ErrUnavailable)
}
