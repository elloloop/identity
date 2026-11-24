package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// observedLogger records every info line a service writes.
func observedLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.InfoLevel)
	return zap.New(core), logs
}

// decisionLine is the one line logged as msg, failing unless exactly one was.
func decisionLine(t *testing.T, logs *observer.ObservedLogs, msg string) map[string]any {
	t.Helper()
	lines := logs.FilterMessage(msg).All()
	require.Len(t, lines, 1, "exactly one %s line", msg)
	return lines[0].ContextMap()
}

// requireNoLine fails when any line was logged as one of msgs.
func requireNoLine(t *testing.T, logs *observer.ObservedLogs, msgs ...string) {
	t.Helper()
	for _, msg := range msgs {
		require.Zero(t, logs.FilterMessage(msg).Len(), "no %s line", msg)
	}
}

// requireNothingPersonal fails when any line carries one of values, an
// address, a token, a password or a name.
func requireNothingPersonal(t *testing.T, logs *observer.ObservedLogs, values ...string) {
	t.Helper()
	for _, entry := range logs.All() {
		for key, v := range entry.ContextMap() {
			for _, value := range values {
				require.NotContains(t, fmt.Sprint(v), value, "%s carries it in %s", entry.Message, key)
			}
		}
	}
}

func TestTenantInvitationDecisionLogs_Read(t *testing.T) {
	t.Run("open_with_an_account", func(t *testing.T) {
		f := newInvitationLookupFixture(true)
		logger, logs := observedLogger()
		f.svc.logger = logger
		token := f.seed("inv-1", InvitationStatusPending, time.Hour)
		seedUser(f.accounts, mInvitee, "", StatusActive)

		_, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"project_id": mTestProject, "tenant_id": mTestTenant, "invitation_id": "inv-1",
			"status": InvitationStatusPending, "account_exists": true,
		}, decisionLine(t, logs, "tenant_invitation_read"))
		requireNothingPersonal(t, logs, mInvitee, token, "Maya Chen", "maya@acme.com")
	})
	t.Run("expired_without_an_account", func(t *testing.T) {
		f := newInvitationLookupFixture(true)
		logger, logs := observedLogger()
		f.svc.logger = logger
		token := f.seed("inv-1", InvitationStatusPending, -time.Minute)

		_, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
		require.NoError(t, err)
		line := decisionLine(t, logs, "tenant_invitation_read")
		require.Equal(t, InvitationStatusExpired, line["status"])
		require.Equal(t, false, line["account_exists"])
	})
	t.Run("account_unanswered_without_a_mailer", func(t *testing.T) {
		f := newInvitationLookupFixture(false)
		logger, logs := observedLogger()
		f.svc.logger = logger
		token := f.seed("inv-1", InvitationStatusRevoked, time.Hour)

		_, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
		require.NoError(t, err)
		line := decisionLine(t, logs, "tenant_invitation_read")
		require.Equal(t, InvitationStatusRevoked, line["status"])
		require.NotContains(t, line, "account_exists", "what is not answered is not logged")
		require.Equal(t, "mail_not_delivered", line["account_exists_withheld"])
	})
	t.Run("account_unanswered_for_a_token_that_left_the_email", func(t *testing.T) {
		f := newInvitationLookupFixture(true)
		logger, logs := observedLogger()
		f.svc.logger = logger
		token := f.seed("inv-1", InvitationStatusPending, time.Hour)
		f.invitations.byID[f.invitations.key(mTestProject, "inv-1")].TokenOnlyInEmail = false
		seedUser(f.accounts, mInvitee, "", StatusActive)

		_, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"project_id": mTestProject, "tenant_id": mTestTenant, "invitation_id": "inv-1",
			"status": InvitationStatusPending, "account_exists_withheld": "token_outside_email",
		}, decisionLine(t, logs, "tenant_invitation_read"))
		requireNothingPersonal(t, logs, mInvitee, token)
	})
	t.Run("not_found", func(t *testing.T) {
		f := newInvitationLookupFixture(true)
		logger, logs := observedLogger()
		f.svc.logger = logger
		token := randomToken(invitationTokenBytes)

		_, err := f.svc.GetTenantInvitation(withProject(mTestProject), token)
		require.ErrorIs(t, err, ErrNotFound)
		require.Equal(t, map[string]any{"project_id": mTestProject, "reason": "not_found"},
			decisionLine(t, logs, "tenant_invitation_read_refused"))
		requireNoLine(t, logs, "tenant_invitation_read")
		requireNothingPersonal(t, logs, token)
	})
}

func TestTenantInvitationDecisionLogs_SignUp(t *testing.T) {
	for _, tc := range []struct {
		reason string
		// setup prepares the refusal and returns the request's context and token.
		setup func(t *testing.T, f *invitationSignupFixture) (context.Context, string)
		// password is the password signed up with, signupPassword when empty.
		password string
		extra    map[string]any
		noIDs    bool
	}{
		{reason: "not_opted_in", noIDs: true, setup: func(t *testing.T, f *invitationSignupFixture) (context.Context, string) {
			t.Helper()
			return invitationSignupScope(t, `{"access":{"mode":"open"}}`), f.pendingInvitation()
		}},
		{reason: "mail_not_delivered", noIDs: true, setup: func(t *testing.T, f *invitationSignupFixture) (context.Context, string) {
			t.Helper()
			f.svc.WithMailDelivery(false)
			return inviteOnlyScope(t), f.pendingInvitation()
		}},
		{reason: "not_found", noIDs: true, setup: func(t *testing.T, f *invitationSignupFixture) (context.Context, string) {
			t.Helper()
			f.pendingInvitation()
			return inviteOnlyScope(t), randomToken(invitationTokenBytes)
		}},
		{reason: "token_outside_email", setup: func(t *testing.T, f *invitationSignupFixture) (context.Context, string) {
			t.Helper()
			token := f.pendingInvitation()
			f.handOut("inv-1")
			return inviteOnlyScope(t), token
		}},
		{reason: "invitation_closed", extra: map[string]any{"status": InvitationStatusRevoked}, setup: func(t *testing.T, f *invitationSignupFixture) (context.Context, string) {
			t.Helper()
			return inviteOnlyScope(t), f.invite("inv-1", mTestTenant, InvitationStatusRevoked, time.Hour, time.Hour)
		}},
		{reason: "invitation_not_open", setup: func(t *testing.T, f *invitationSignupFixture) (context.Context, string) {
			t.Helper()
			f.invitations.unqualified = map[string]bool{mTestTenant: true}
			return inviteOnlyScope(t), f.pendingInvitation()
		}},
		{reason: "account_exists", setup: func(t *testing.T, f *invitationSignupFixture) (context.Context, string) {
			t.Helper()
			seedUser(f.repo, signupInvitee, "", StatusActive)
			return inviteOnlyScope(t), f.pendingInvitation()
		}},
		{reason: "login_policy", setup: func(t *testing.T, f *invitationSignupFixture) (context.Context, string) {
			t.Helper()
			g := claimedPasswordOnlyGovernance()
			g.Policies.(*fakePolicyStore).byTenant["proj-1|tenant-acme"].SSORequired = true
			f.svc.WithLoginGovernance(g)
			return inviteOnlyScope(t), f.pendingInvitation()
		}},
		{reason: "password_rule", password: "Sh0rt!a", setup: func(t *testing.T, f *invitationSignupFixture) (context.Context, string) {
			t.Helper()
			return inviteOnlyScope(t), f.pendingInvitation()
		}},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			f := newInvitationSignupFixture(t)
			logger, logs := observedLogger()
			f.svc.logger = logger
			ctx, token := tc.setup(t, f)
			password := tc.password
			if password == "" {
				password = signupPassword
			}

			_, err := f.signUp(ctx, token, signupName, password)
			require.Error(t, err)
			want := map[string]any{"project_id": mTestProject, "reason": tc.reason}
			if !tc.noIDs {
				want["tenant_id"], want["invitation_id"] = mTestTenant, "inv-1"
			}
			for k, v := range tc.extra {
				want[k] = v
			}
			require.Equal(t, want, decisionLine(t, logs, "tenant_invitation_signup_refused"))
			requireNoLine(t, logs, "tenant_invitation_signup_created", "signup_admitted_by_tenant_invitation")
			requireNothingPersonal(t, logs, signupInvitee, token, signupName, password)
		})
	}

	t.Run("deny_layer_names_the_domain_only", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		logger, logs := observedLogger()
		f.svc.logger = logger
		raw := randomToken(invitationTokenBytes)
		f.invitations.byID[f.invitations.key(mTestProject, "inv-1")] = &TenantInvitation{
			ID: "inv-1", ProjectID: mTestProject, TenantID: mTestTenant, TokenHash: sha256Hex(raw),
			Email: "ravi@gmail.com", InvitedBy: mAdminID, Role: RoleMember, Status: InvitationStatusPending,
			ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli(), TokenOnlyInEmail: true,
		}
		ctx := invitationSignupScope(t, `{"access":{"mode":"invite","admit_tenant_invitations":true,"block_public_email_domains":true}}`)

		_, err := f.signUp(ctx, raw, signupName, signupPassword)
		require.ErrorIs(t, err, ErrAccessNotAllowed)
		require.Equal(t, map[string]any{
			"project_id": mTestProject, "tenant_id": mTestTenant, "invitation_id": "inv-1",
			"reason": "deny_layer", "email_domain": "gmail.com",
		}, decisionLine(t, logs, "tenant_invitation_signup_refused"))
		requireNothingPersonal(t, logs, "ravi@gmail.com", raw)
	})

	t.Run("created", func(t *testing.T) {
		f := newInvitationSignupFixture(t)
		logger, logs := observedLogger()
		f.svc.logger = logger
		token := f.pendingInvitation()

		res, err := f.signUp(inviteOnlyScope(t), token, signupName, signupPassword)
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"project_id": mTestProject, "tenant_id": mTestTenant, "invitation_id": "inv-1", "user_id": res.User.ID,
		}, decisionLine(t, logs, "tenant_invitation_signup_created"))
		decisionLine(t, logs, "signup_admitted_by_tenant_invitation")
		requireNoLine(t, logs, "tenant_invitation_signup_refused")
		requireNothingPersonal(t, logs, signupInvitee, token, signupName, signupPassword)
	})
}

func TestTenantInvitationDecisionLogs_Accept(t *testing.T) {
	for _, tc := range []struct {
		reason string
		// setup prepares the refusal and returns the caller and the token.
		setup func(f *invitationLookupFixture) (string, string)
		extra map[string]any
		noIDs bool
	}{
		{reason: "not_found", noIDs: true, setup: func(f *invitationLookupFixture) (string, string) {
			f.users.put(mTestProject, mInviteeID, mInvitee)
			return mInviteeID, randomToken(invitationTokenBytes)
		}},
		{reason: "invitation_closed", extra: map[string]any{"status": InvitationStatusAccepted}, setup: func(f *invitationLookupFixture) (string, string) {
			f.users.put(mTestProject, mInviteeID, mInvitee)
			return mInviteeID, f.seed("inv-1", InvitationStatusAccepted, time.Hour)
		}},
		{reason: "invitation_closed", extra: map[string]any{"status": InvitationStatusExpired}, setup: func(f *invitationLookupFixture) (string, string) {
			f.users.put(mTestProject, mInviteeID, mInvitee)
			return mInviteeID, f.seed("inv-1", InvitationStatusPending, -time.Minute)
		}},
		{reason: "caller_not_found", setup: func(f *invitationLookupFixture) (string, string) {
			return mInviteeID, f.seed("inv-1", InvitationStatusPending, time.Hour)
		}},
		{reason: "email_mismatch", setup: func(f *invitationLookupFixture) (string, string) {
			f.users.put(mTestProject, mInviteeID, "someone-else@acme.com")
			return mInviteeID, f.seed("inv-1", InvitationStatusPending, time.Hour)
		}},
		{reason: "email_unverified", setup: func(f *invitationLookupFixture) (string, string) {
			f.users.set(mTestProject, &User{ID: mInviteeID, Email: mInvitee})
			return mInviteeID, f.seed("inv-1", InvitationStatusPending, time.Hour)
		}},
		{reason: "tenant_not_governable", setup: func(f *invitationLookupFixture) (string, string) {
			f.users.put(mTestProject, mInviteeID, mInvitee)
			f.tenants.byID[mTestProject+"/"+mTestTenant].Status = TenantStatusSuspended
			return mInviteeID, f.seed("inv-1", InvitationStatusPending, time.Hour)
		}},
		{reason: "member_suspended", setup: func(f *invitationLookupFixture) (string, string) {
			f.users.put(mTestProject, mInviteeID, mInvitee)
			_, _ = f.memberships.UpsertMembership(context.Background(), &TenantMembership{
				ProjectID: mTestProject, TenantID: mTestTenant, UserID: mInviteeID,
				Source: MembershipSourceInvited, Role: RoleMember, Status: MembershipStatusSuspended,
			})
			return mInviteeID, f.seed("inv-1", InvitationStatusPending, time.Hour)
		}},
	} {
		name := tc.reason
		if status, ok := tc.extra["status"]; ok {
			name += "_" + fmt.Sprint(status)
		}
		t.Run(name, func(t *testing.T) {
			f := newInvitationLookupFixture(true)
			logger, logs := observedLogger()
			f.svc.logger = logger
			caller, token := tc.setup(f)

			_, err := f.svc.AcceptTenantInvitation(withProject(mTestProject), caller, token)
			require.Error(t, err)
			want := map[string]any{"project_id": mTestProject, "user_id": caller, "reason": tc.reason}
			if !tc.noIDs {
				want["tenant_id"], want["invitation_id"] = mTestTenant, "inv-1"
			}
			for k, v := range tc.extra {
				want[k] = v
			}
			require.Equal(t, want, decisionLine(t, logs, "tenant_invitation_accept_refused"))
			requireNoLine(t, logs, "tenant_invitation_accepted")
			requireNothingPersonal(t, logs, mInvitee, "someone-else@acme.com", token)
		})
	}

	t.Run("membership_added", func(t *testing.T) {
		f := newInvitationLookupFixture(true)
		logger, logs := observedLogger()
		f.svc.logger = logger
		f.users.put(mTestProject, mInviteeID, mInvitee)
		token := f.seed("inv-1", InvitationStatusPending, time.Hour)

		_, err := f.svc.AcceptTenantInvitation(withProject(mTestProject), mInviteeID, token)
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"project_id": mTestProject, "tenant_id": mTestTenant, "invitation_id": "inv-1", "user_id": mInviteeID,
			"role": RoleAdmin, "source": MembershipSourceInvited, "changed": true,
		}, decisionLine(t, logs, "tenant_invitation_accepted"))
		requireNoLine(t, logs, "tenant_invitation_accept_refused")
		requireNothingPersonal(t, logs, mInvitee, token)
	})
	t.Run("member_kept_as_is", func(t *testing.T) {
		f := newInvitationLookupFixture(true)
		logger, logs := observedLogger()
		f.svc.logger = logger
		f.users.put(mTestProject, mInviteeID, mInvitee)
		f.seedMember(mTestProject, mTestTenant, mInviteeID, RoleOwner)
		token := f.seed("inv-1", InvitationStatusPending, time.Hour)

		_, err := f.svc.AcceptTenantInvitation(withProject(mTestProject), mInviteeID, token)
		require.NoError(t, err)
		line := decisionLine(t, logs, "tenant_invitation_accepted")
		require.Equal(t, RoleOwner, line["role"], "an owner accepting an admin invitation stays the owner")
		require.Equal(t, false, line["changed"])
	})
}
