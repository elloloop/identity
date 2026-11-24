package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

const (
	signupInvitee  = "ravi@acme.com"
	signupPassword = "Corr3ct!Horse"
	signupName     = "Ravi Kumar"
)

// invitationSignupFixture is an AuthService over an invite project that lets
// invitations create accounts, whose mailer delivers, with one invitation
// store a MembershipService can share to accept afterwards.
type invitationSignupFixture struct {
	svc         *AuthService
	repo        *fakeRepo
	invitations *fakeInvitationStore
	audit       *recordingAuditWriter
	autoFormer  *fakeAutoFormer
}

func newInvitationSignupFixture(t *testing.T) *invitationSignupFixture {
	t.Helper()
	repo := newFakeRepo()
	w := newRecordingAuditWriter()
	af := &fakeAutoFormer{}
	invitations := newFakeInvitationStore()
	svc := newTestAuthServiceWithAudit(t, repo, w).
		WithOpenInvitations(invitations).
		WithMailDelivery(true).
		WithTenantAutoFormer(af)
	return &invitationSignupFixture{svc: svc, repo: repo, invitations: invitations, audit: w, autoFormer: af}
}

// invitationSignupScope is a request for mTestProject under configJSON, as
// the control plane resolves it.
func invitationSignupScope(t *testing.T, configJSON string) context.Context {
	t.Helper()
	cfg, err := ParseProjectConfig(configJSON)
	require.NoError(t, err)
	return WithProjectScope(context.Background(), &ProjectScope{ProjectID: mTestProject, Access: cfg.Access, Accounts: cfg.Accounts})
}

// inviteOnlyScope is a request for mTestProject, an invite project that lets
// invitations create accounts.
func inviteOnlyScope(t *testing.T) context.Context {
	t.Helper()
	return invitationSignupScope(t, inviteOnlyJSON)
}

// invite stores an invitation of tenantID to signupInvitee in status,
// expiring expiresIn from now, created createdAgo before now, whose token
// went only into its email, and returns the raw token that email would carry.
func (f *invitationSignupFixture) invite(id, tenantID, status string, expiresIn, createdAgo time.Duration) string {
	raw := randomToken(invitationTokenBytes)
	now := time.Now()
	f.invitations.byID[f.invitations.key(mTestProject, id)] = &TenantInvitation{
		ID: id, ProjectID: mTestProject, TenantID: tenantID, TokenHash: sha256Hex(raw),
		Email: signupInvitee, InvitedBy: mAdminID, Role: RoleMember, Status: status,
		ExpiresAtMs: now.Add(expiresIn).UnixMilli(), CreatedAtMs: now.Add(-createdAgo).UnixMilli(),
		TokenOnlyInEmail: true,
	}
	return raw
}

// handOut records that invitation id's token did not go only into its
// email, as for one created without a mailer that delivers, or stored before
// that was recorded.
func (f *invitationSignupFixture) handOut(id string) {
	f.invitations.byID[f.invitations.key(mTestProject, id)].TokenOnlyInEmail = false
}

func (f *invitationSignupFixture) pendingInvitation() string {
	return f.invite("inv-1", mTestTenant, InvitationStatusPending, time.Hour, time.Minute)
}

func (f *invitationSignupFixture) signUp(ctx context.Context, token, name, password string) (*LoginResult, error) {
	return f.svc.SignUpWithTenantInvitation(ctx, token, name, password, "203.0.113.9", "invitation-test")
}

func (f *invitationSignupFixture) requireNoAccount(t *testing.T) {
	t.Helper()
	u, err := f.repo.FindUserByEmail(context.Background(), signupInvitee)
	require.NoError(t, err)
	require.Nil(t, u, "no account was created")
}

func (f *invitationSignupFixture) status(id string) string {
	return f.invitations.byID[f.invitations.key(mTestProject, id)].Status
}

func TestSignUpWithTenantInvitation_CreatesAVerifiedAccountAndSignsIn(t *testing.T) {
	f := newInvitationSignupFixture(t)
	token := f.pendingInvitation()

	res, err := f.signUp(invitationSignupScope(t, inviteOnlyJSON), " "+token+" ", "  "+signupName+" ", signupPassword)
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.NotEmpty(t, res.RefreshToken)
	require.Equal(t, secondsToInt32(f.svc.cfg.JWTExpirySeconds), res.ExpiresIn)
	require.Equal(t, signupInvitee, res.User.Email)
	require.Equal(t, signupName, res.User.Name, "the name is trimmed")
	require.Empty(t, res.User.PasswordHash, "the hash is not handed back")

	stored, err := f.repo.FindUserByEmail(context.Background(), signupInvitee)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Equal(t, res.User.ID, stored.ID)
	require.True(t, stored.EmailVerified, "the emailed link proves the address")
	require.NotZero(t, stored.EmailVerifiedAt)
	require.Equal(t, StatusActive, stored.Status)
	require.True(t, passwords.Verify(signupPassword, stored.PasswordHash))

	require.Equal(t, InvitationStatusPending, f.status("inv-1"), "signing up does not accept the invitation")
	require.Empty(t, f.autoFormer.calls, "the account forms no tenant from its email's domain")
}

// The account is admitted as a proven sign-up is, by the token's own
// invitation, and its sign-in is audited.
func TestSignUpWithTenantInvitation_IsAudited(t *testing.T) {
	f := newInvitationSignupFixture(t)
	token := f.pendingInvitation()

	res, err := f.signUp(invitationSignupScope(t, inviteOnlyJSON), token, signupName, signupPassword)
	require.NoError(t, err)

	require.Equal(t, 1, f.audit.countByEventTypeActorTarget(string(audit.EventSignupAdmittedByInvitation), "", res.User.ID))
	require.Equal(t, [][2]string{{"203.0.113.9", "invitation-test"}}, f.audit.clientsOf(string(audit.EventSignupAdmittedByInvitation)))
	admitted := f.audit.detailsOf(string(audit.EventSignupAdmittedByInvitation))
	require.Len(t, admitted, 1)
	require.Equal(t, "inv-1", admitted[0]["invitation_id"])
	require.Equal(t, mTestTenant, admitted[0]["tenant_id"])
	require.Equal(t, mAdminID, admitted[0]["invited_by"])
	require.Equal(t, 1, f.audit.countByEventTypeAndDetail(string(audit.EventLoginSuccess), "method", "tenant_invitation_signup"))
}

// The new account joins the tenant only by accepting the invitation it
// signed up from, which it can do at once with the session it was given.
func TestSignUpWithTenantInvitation_TheInvitationIsThenAccepted(t *testing.T) {
	f := newInvitationSignupFixture(t)
	token := f.pendingInvitation()
	ctx := invitationSignupScope(t, inviteOnlyJSON)
	res, err := f.signUp(ctx, token, signupName, signupPassword)
	require.NoError(t, err)

	memberships := newFakeMembershipStore()
	tenants := newFakeTenantStore()
	tenants.ensure(mTestProject, mTestTenant)
	members := NewMembershipService(f.invitations, memberships, tenants, RepositoryUserDirectory(f.repo), &recordingMailer{}, true, &config.Config{}, nil)
	before, err := memberships.ListMembershipsForUser(ctx, mTestProject, res.User.ID)
	require.NoError(t, err)
	require.Empty(t, before, "the account is in no tenant until it accepts")

	m, err := members.AcceptTenantInvitation(ctx, res.User.ID, token)
	require.NoError(t, err)
	require.Equal(t, mTestTenant, m.TenantID)
	require.Equal(t, RoleMember, m.Role)
	require.Equal(t, InvitationStatusAccepted, f.status("inv-1"))

	_, err = f.signUp(ctx, token, signupName, signupPassword)
	require.ErrorIs(t, err, ErrInvitationUsed, "an accepted invitation creates no second account")
}

func TestSignUpWithTenantInvitation_ClosedInvitationIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    string
		expiresIn time.Duration
		want      error
	}{
		{"accepted", InvitationStatusAccepted, time.Hour, ErrInvitationUsed},
		{"revoked", InvitationStatusRevoked, time.Hour, ErrInvitationRevoked},
		{"expired_recorded", InvitationStatusExpired, -time.Minute, ErrInvitationExpired},
		{"pending_past_expiry", InvitationStatusPending, -time.Minute, ErrInvitationExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInvitationSignupFixture(t)
			token := f.invite("inv-1", mTestTenant, tc.status, tc.expiresIn, time.Hour)

			_, err := f.signUp(invitationSignupScope(t, inviteOnlyJSON), token, signupName, signupPassword)
			require.ErrorIs(t, err, tc.want)
			f.requireNoAccount(t)
			require.Equal(t, tc.status, f.status("inv-1"), "a refusal records nothing on the invitation")
		})
	}
}

func TestSignUpWithTenantInvitation_UnknownTokenIsNotFound(t *testing.T) {
	f := newInvitationSignupFixture(t)
	f.pendingInvitation()
	ctx := invitationSignupScope(t, inviteOnlyJSON)

	_, err := f.signUp(ctx, randomToken(invitationTokenBytes), signupName, signupPassword)
	require.ErrorIs(t, err, ErrNotFound)

	other := randomToken(invitationTokenBytes)
	f.invitations.byID[f.invitations.key("proj-2", "inv-other")] = &TenantInvitation{
		ID: "inv-other", ProjectID: "proj-2", TenantID: mTestTenant, TokenHash: sha256Hex(other),
		Email: signupInvitee, InvitedBy: mAdminID, Role: RoleMember, Status: InvitationStatusPending,
		ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(), TokenOnlyInEmail: true,
	}
	_, err = f.signUp(ctx, other, signupName, signupPassword)
	require.ErrorIs(t, err, ErrNotFound, "another project's invitation is not this project's")
	f.requireNoAccount(t)
}

// An address an account holds, as its email or as a recovery email, gets no
// second account: the person signs in instead.
func TestSignUpWithTenantInvitation_AddressWithAnAccountIsRefused(t *testing.T) {
	t.Run("account_email", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		token := f.pendingInvitation()
		existing := seedUser(f.repo, signupInvitee, "", StatusActive)

		_, err := f.signUp(invitationSignupScope(t, inviteOnlyJSON), token, signupName, signupPassword)
		require.ErrorIs(t, err, ErrAlreadyExists)
		u, _ := f.repo.FindUserByEmail(context.Background(), signupInvitee)
		require.Equal(t, existing.ID, u.ID)
		require.Empty(t, u.PasswordHash, "the existing account is left as it was")
	})
	t.Run("recovery_email", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		token := f.pendingInvitation()
		ctx := invitationSignupScope(t, inviteOnlyJSON)
		holder := seedUser(f.repo, "holder@example.com", "", StatusActive)
		require.NoError(t, f.repo.AddRecoveryEmail(ctx, &RecoveryEmail{UserID: holder.ID, Email: signupInvitee}, 5))

		_, err := f.signUp(ctx, token, signupName, signupPassword)
		require.ErrorIs(t, err, ErrAlreadyExists)
		f.requireNoAccount(t)
	})
	t.Run("created_meanwhile", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		token := f.pendingInvitation()
		f.repo.createUserHook = func() {
			f.repo.createUserHook = nil
			seedUser(f.repo, signupInvitee, "", StatusActive)
		}

		_, err := f.signUp(invitationSignupScope(t, inviteOnlyJSON), token, signupName, signupPassword)
		require.ErrorIs(t, err, ErrAlreadyExists, "a sign-up that loses the race is told the address is taken")
	})
}

func TestSignUpWithTenantInvitation_PasswordRules(t *testing.T) {
	t.Run("blank", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		_, err := f.signUp(inviteOnlyScope(t), f.pendingInvitation(), signupName, "")
		require.ErrorIs(t, err, ErrInvalidArgument)
		f.requireNoAccount(t)
	})
	t.Run("too_weak", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		for _, weak := range []string{"Sh0rt!a", "alllowercase1!", "NoDigitsHere!", "NoSymbols123a", "P@ssw0rd"} {
			_, err := f.signUp(inviteOnlyScope(t), f.pendingInvitation(), signupName, weak)
			require.ErrorIs(t, err, ErrWeakPassword, weak)
		}
		f.requireNoAccount(t)
	})
	t.Run("the_address_tenants_policy", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		f.svc.WithLoginGovernance(withPasswordMinLength(14))
		const thirteen = "Aa1!aaaaaaaaa"
		require.NoError(t, validatePasswordStrength(thirteen), "the deployment's own rules allow it")

		_, err := f.signUp(inviteOnlyScope(t), f.pendingInvitation(), signupName, thirteen)
		require.ErrorIs(t, err, ErrWeakPassword, "acme.com's tenant asks for 14")
		f.requireNoAccount(t)

		_, err = f.signUp(inviteOnlyScope(t), f.pendingInvitation(), signupName, thirteen+"a")
		require.NoError(t, err)
	})
}

// The address's tenant decides how its people sign in, so a password account
// is not made where its policy would refuse the password sign-in.
func TestSignUpWithTenantInvitation_LoginPolicyOfTheAddress(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy func(*LoginPolicy)
		want   error
	}{
		{"sso_required", func(p *LoginPolicy) { p.SSORequired = true }, ErrSSORequired},
		{"password_not_allowed", func(p *LoginPolicy) { p.AllowedMethods = LoginMethodOAuth }, ErrPermissionDenied},
		{"second_factor_required", func(p *LoginPolicy) { p.Require2FA = true }, ErrTotpRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInvitationSignupFixture(t)
			g := claimedPasswordOnlyGovernance()
			tc.policy(g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"])
			f.svc.WithLoginGovernance(g)

			_, err := f.signUp(invitationSignupScope(t, inviteOnlyJSON), f.pendingInvitation(), signupName, signupPassword)
			require.ErrorIs(t, err, tc.want)
			f.requireNoAccount(t)
		})
	}
}

func TestSignUpWithTenantInvitation_NameRules(t *testing.T) {
	for name, given := range map[string]string{
		"blank":          "   ",
		"too_long":       strings.Repeat("a", accountNameMaxRunes+1),
		"control":        "Ravi\x07Kumar",
		"bidi_override":  "Ravi\u202eKumar",
		"line_separator": "Ravi\u2028Kumar",
	} {
		t.Run(name, func(t *testing.T) {
			f := newInvitationSignupFixture(t)
			_, err := f.signUp(invitationSignupScope(t, inviteOnlyJSON), f.pendingInvitation(), given, signupPassword)
			require.ErrorIs(t, err, ErrInvalidArgument)
			f.requireNoAccount(t)
		})
	}
}

// Without the project's opt-in an invitation creates no account, and the
// refusal comes before the token is looked up, so it says nothing about it.
func TestSignUpWithTenantInvitation_RefusedUnlessTheProjectOptsIn(t *testing.T) {
	for name, configJSON := range map[string]string{
		"invite_without_opt_in": `{"access":{"mode":"invite"}}`,
		"open":                  `{"access":{"mode":"open"}}`,
		"allowlist":             `{"access":{"mode":"allowlist","allowed_domains":["acme.com"]}}`,
		"admin_made_accounts":   `{"access":{"mode":"invite","admit_tenant_invitations":true},"accounts":{"email_signup":"admin"}}`,
		"email_accounts_off":    `{"access":{"mode":"invite","admit_tenant_invitations":true},"accounts":{"email_signup":"off"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newInvitationSignupFixture(t)
			token := f.pendingInvitation()
			ctx := invitationSignupScope(t, configJSON)

			_, err := f.signUp(ctx, token, signupName, signupPassword)
			require.ErrorIs(t, err, ErrInvitationSignupUnavailable)
			_, unknownErr := f.signUp(ctx, randomToken(invitationTokenBytes), signupName, signupPassword)
			require.ErrorIs(t, unknownErr, ErrInvitationSignupUnavailable, "the same refusal for a token no invitation has")
			f.requireNoAccount(t)
		})
	}

	f := newInvitationSignupFixture(t)
	_, err := f.signUp(context.Background(), f.pendingInvitation(), signupName, signupPassword)
	require.ErrorIs(t, err, ErrPermissionDenied, "no project, no invitation")
	f.requireNoAccount(t)
}

// Without a mailer that delivers, the inviter was handed the token, so it
// proves nothing about the address and creates no account.
func TestSignUpWithTenantInvitation_RefusedWhereMailIsNotDelivered(t *testing.T) {
	f := newInvitationSignupFixture(t)
	f.svc.WithMailDelivery(false)
	token := f.pendingInvitation()
	ctx := invitationSignupScope(t, inviteOnlyJSON)

	_, err := f.signUp(ctx, token, signupName, signupPassword)
	require.ErrorIs(t, err, ErrInvitationSignupUnavailable)
	_, err = f.signUp(ctx, randomToken(invitationTokenBytes), signupName, signupPassword)
	require.ErrorIs(t, err, ErrInvitationSignupUnavailable)
	f.requireNoAccount(t)
	require.Equal(t, InvitationStatusPending, f.status("inv-1"))
}

// A token that did not go only into its invitation's email, handed to the
// inviter by a server without mail or stored before that was recorded,
// proves nothing about the address: it creates no account though the mailer
// delivers now, with the refusal a server without mail gives, whatever the
// invitation's status. The invitee still accepts it after a sign-in that
// proves the address.
func TestSignUpWithTenantInvitation_RefusedWhenTheTokenLeftTheEmail(t *testing.T) {
	for name, status := range map[string]string{
		"pending": InvitationStatusPending,
		"revoked": InvitationStatusRevoked,
	} {
		t.Run(name, func(t *testing.T) {
			f := newInvitationSignupFixture(t)
			token := f.invite("inv-1", mTestTenant, status, time.Hour, time.Minute)
			f.handOut("inv-1")

			_, err := f.signUp(inviteOnlyScope(t), token, signupName, signupPassword)
			require.ErrorIs(t, err, ErrInvitationSignupUnavailable)
			f.requireNoAccount(t)
			require.Equal(t, status, f.status("inv-1"), "a refusal records nothing on the invitation")
		})
	}

	t.Run("accepted_after_a_proven_sign_in", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		token := f.pendingInvitation()
		f.handOut("inv-1")
		ctx := inviteOnlyScope(t)
		_, err := f.signUp(ctx, token, signupName, signupPassword)
		require.ErrorIs(t, err, ErrInvitationSignupUnavailable)

		id, err := f.repo.CreateUser(ctx, &User{Email: signupInvitee, Status: StatusActive, EmailVerified: true})
		require.NoError(t, err)
		tenants := newFakeTenantStore()
		tenants.ensure(mTestProject, mTestTenant)
		members := NewMembershipService(f.invitations, newFakeMembershipStore(), tenants, RepositoryUserDirectory(f.repo), &recordingMailer{}, true, &config.Config{}, nil)
		m, err := members.AcceptTenantInvitation(ctx, id, token)
		require.NoError(t, err)
		require.Equal(t, mTestTenant, m.TenantID)
		require.Equal(t, InvitationStatusAccepted, f.status("inv-1"))
	})
}

// The token's own invitation must be one that may create an account: an
// older invitation still counts while a newer one is open, and another open
// invitation to the address does not stand in for one that is not.
func TestSignUpWithTenantInvitation_TheTokensOwnInvitationMustBeOpen(t *testing.T) {
	t.Run("older_of_two", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		older := f.invite("inv-older", mTestTenant, InvitationStatusPending, time.Hour, time.Hour)
		f.invite("inv-newer", "tenant-2", InvitationStatusPending, time.Hour, time.Minute)

		_, err := f.signUp(inviteOnlyScope(t), older, signupName, signupPassword)
		require.NoError(t, err)
		admitted := f.audit.detailsOf(string(audit.EventSignupAdmittedByInvitation))
		require.Len(t, admitted, 1)
		require.Equal(t, "inv-older", admitted[0]["invitation_id"], "the token's invitation admitted the account")
	})
	t.Run("not_open_though_another_is", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		f.invite("inv-open", mTestTenant, InvitationStatusPending, time.Hour, time.Hour)
		closed := f.invite("inv-closed", "tenant-self-service", InvitationStatusPending, time.Hour, time.Minute)
		f.invitations.unqualified = map[string]bool{"tenant-self-service": true}

		_, err := f.signUp(inviteOnlyScope(t), closed, signupName, signupPassword)
		require.ErrorIs(t, err, ErrPermissionDenied)
		f.requireNoAccount(t)
	})
}

func TestSignUpWithTenantInvitation_DenyLayerRefusesTheAddress(t *testing.T) {
	f := newInvitationSignupFixture(t)
	raw := randomToken(invitationTokenBytes)
	f.invitations.byID[f.invitations.key(mTestProject, "inv-public")] = &TenantInvitation{
		ID: "inv-public", ProjectID: mTestProject, TenantID: mTestTenant, TokenHash: sha256Hex(raw),
		Email: "ravi@gmail.com", InvitedBy: mAdminID, Role: RoleMember, Status: InvitationStatusPending,
		ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(), TokenOnlyInEmail: true,
	}
	ctx := invitationSignupScope(t, `{"access":{"mode":"invite","admit_tenant_invitations":true,"block_public_email_domains":true}}`)

	_, err := f.signUp(ctx, raw, signupName, signupPassword)
	require.ErrorIs(t, err, ErrAccessNotAllowed)
	u, _ := f.repo.FindUserByEmail(context.Background(), "ravi@gmail.com")
	require.Nil(t, u)
}

func TestSignUpWithTenantInvitation_DeploymentGatesAndInputs(t *testing.T) {
	t.Run("local_auth_off", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		f.svc.cfg.AuthAllowLocal = false
		_, err := f.signUp(inviteOnlyScope(t), f.pendingInvitation(), signupName, signupPassword)
		require.ErrorIs(t, err, ErrLocalAuthDisabled)
	})
	t.Run("password_signup_off", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		f.svc.cfg.PasswordSignupEnabled = false
		_, err := f.signUp(inviteOnlyScope(t), f.pendingInvitation(), signupName, signupPassword)
		require.ErrorIs(t, err, ErrSignupDisabled)
	})
	t.Run("no_invitation_store", func(t *testing.T) {
		svc := newTestAuthService(t, newFakeRepo()).WithMailDelivery(true)
		_, err := svc.SignUpWithTenantInvitation(inviteOnlyScope(t), "token", signupName, signupPassword, "", "")
		require.ErrorIs(t, err, ErrUnimplemented)
	})
	t.Run("blank_token", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		_, err := f.signUp(inviteOnlyScope(t), "  ", signupName, signupPassword)
		require.ErrorIs(t, err, ErrInvalidArgument)
	})
}

func TestSignUpWithTenantInvitation_LookupFailuresAreReturned(t *testing.T) {
	boom := errors.New("database unavailable")
	for name, fail := range map[string]func(*invitationSignupFixture){
		"invitation":      func(f *invitationSignupFixture) { f.invitations.getErr = boom },
		"open_invitation": func(f *invitationSignupFixture) { f.invitations.openErr = boom },
	} {
		t.Run(name, func(t *testing.T) {
			f := newInvitationSignupFixture(t)
			token := f.pendingInvitation()
			fail(f)

			_, err := f.signUp(invitationSignupScope(t, inviteOnlyJSON), token, signupName, signupPassword)
			require.ErrorIs(t, err, boom)
			f.requireNoAccount(t)
		})
	}
}
