package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/pkg/audit"
)

const inviteOnlyJSON = `{"access":{"mode":"invite","admit_tenant_invitations":true}}`

type invitationSpec struct {
	projectID string
	email     string
	status    string
	expiresIn time.Duration
}

func invitationsWith(specs ...invitationSpec) *fakeInvitationStore {
	store := newFakeInvitationStore()
	now := time.Now()
	for i, spec := range specs {
		id := "inv-seeded-" + string(rune('a'+i))
		store.byID[store.key(spec.projectID, id)] = &TenantInvitation{
			ID: id, ProjectID: spec.projectID, TenantID: "tenant-1", Email: spec.email,
			Role: RoleMember, Status: spec.status,
			ExpiresAtMs: now.Add(spec.expiresIn).UnixMilli(), CreatedAtMs: now.UnixMilli(),
		}
	}
	return store
}

func pending(email string) invitationSpec {
	return invitationSpec{projectID: "project-a", email: email, status: InvitationStatusPending, expiresIn: time.Hour}
}

func invitedOAuthSignIn(ctx context.Context, svc *AuthService, email string) error {
	_, err := svc.OAuthLogin(ctx, OAuthLoginParams{
		Code: fakeOAuthCode(email, "N", "", "google"), Provider: "google", RedirectURI: "https://app/cb",
		IPAddr: "203.0.113.9", UserAgent: "invited-test",
	})
	return err
}

func TestInviteOnly_OAuthSignupAdmittedByOpenInvitation(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo).WithOpenInvitations(invitationsWith(pending("new@example.com")))

	require.NoError(t, invitedOAuthSignIn(accessScope(t, inviteOnlyJSON), svc, "new@example.com"))

	u, _ := repo.FindUserByEmail(context.Background(), "new@example.com")
	require.NotNil(t, u, "an invited address gets its account")
	assert.True(t, u.EmailVerified)
}

func TestInviteOnly_OAuthSignupRefusedWithoutAnOpenInvitation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		store  *fakeInvitationStore
		signIn string
	}{
		{"no_invitation", invitationsWith(), "new@example.com"},
		{"expired", invitationsWith(invitationSpec{"project-a", "new@example.com", InvitationStatusPending, -time.Minute}), "new@example.com"},
		{"accepted", invitationsWith(invitationSpec{"project-a", "new@example.com", InvitationStatusAccepted, time.Hour}), "new@example.com"},
		{"revoked", invitationsWith(invitationSpec{"project-a", "new@example.com", InvitationStatusRevoked, time.Hour}), "new@example.com"},
		{"other_email", invitationsWith(pending("someone@example.com")), "new@example.com"},
		{"other_project", invitationsWith(invitationSpec{"project-b", "new@example.com", InvitationStatusPending, time.Hour}), "new@example.com"},
		{"tag_not_proven_outside_gmail", invitationsWith(pending("new@example.com")), "new+x@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo).WithOpenInvitations(tc.store)

			err := invitedOAuthSignIn(accessScope(t, inviteOnlyJSON), svc, tc.signIn)

			require.ErrorIs(t, err, ErrSignupByInvitationOnly, "refused exactly as an uninvited sign-up")
			u, _ := repo.FindUserByEmail(context.Background(), "new@example.com")
			assert.Nil(t, u)
		})
	}
}

func TestInviteOnly_OAuthSignupWithoutAnInvitationReaderIsRefused(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	require.ErrorIs(t, invitedOAuthSignIn(accessScope(t, inviteOnlyJSON), svc, "new@example.com"), ErrSignupByInvitationOnly)
}

func TestInviteOnly_InvitationLookupFailureRefuses(t *testing.T) {
	store := invitationsWith(pending("new@example.com"))
	store.openErr = errors.New("database unavailable")
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo).WithOpenInvitations(store)

	require.ErrorIs(t, invitedOAuthSignIn(accessScope(t, inviteOnlyJSON), svc, "new@example.com"), ErrSignupByInvitationOnly)
}

func TestInviteOnly_DenyLayerRefusesAnInvitedAddress(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo).WithOpenInvitations(invitationsWith(pending("new@gmail.com")))
	ctx := accessScope(t, `{"access":{"mode":"invite","admit_tenant_invitations":true,"block_public_email_domains":true}}`)

	require.ErrorIs(t, invitedOAuthSignIn(ctx, svc, "new@gmail.com"), ErrSignupByInvitationOnly)
	u, _ := repo.FindUserByEmail(context.Background(), "new@gmail.com")
	assert.Nil(t, u)
}

func TestInviteOnly_AdminOnlyEmailAccountsStayClosedToInvitedSignup(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo).WithOpenInvitations(invitationsWith(pending("new@example.com")))
	cfg, err := ParseProjectConfig(`{"access":{"mode":"invite","admit_tenant_invitations":true},"accounts":{"email_signup":"admin"}}`)
	require.NoError(t, err)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-a", Access: cfg.Access, Accounts: cfg.Accounts})

	require.ErrorIs(t, invitedOAuthSignIn(ctx, svc, "new@example.com"), ErrSignupByInvitationOnly)
}

func TestInviteOnly_InvitationsAdmitNobodyUnlessTheProjectOptsIn(t *testing.T) {
	ctx := accessScope(t, `{"access":{"mode":"invite"}}`)
	oauthRepo := newFakeRepo()
	oauth := newTestAuthService(t, oauthRepo).WithOpenInvitations(invitationsWith(pending("new@example.com")))
	require.ErrorIs(t, invitedOAuthSignIn(ctx, oauth, "new@example.com"), ErrSignupByInvitationOnly)
	u, _ := oauthRepo.FindUserByEmail(context.Background(), "new@example.com")
	assert.Nil(t, u)

	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.WithOpenInvitations(invitationsWith(pending("new@example.com")))
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "new@example.com"))
	assert.Empty(t, rec.Sent(), "no code without the opt-in")
	seedEmailLoginCode(t, repo, "new@example.com", "123456")
	_, err := svc.VerifyEmailLoginCode(ctx, "new@example.com", "123456", "1.2.3.4", "a")
	require.ErrorIs(t, err, ErrSignupByInvitationOnly)
}

func TestInviteOnly_NoCodeWhereRedemptionCouldNotCreateTheAccount(t *testing.T) {
	svc, _, rec := newAuthSvcWithMailer(t)
	svc.WithOpenInvitations(invitationsWith(pending("new@example.com")))
	cfg, err := ParseProjectConfig(`{"access":{"mode":"invite","admit_tenant_invitations":true},"accounts":{"email_signup":"admin"}}`)
	require.NoError(t, err)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-a", Access: cfg.Access, Accounts: cfg.Accounts})

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "new@example.com"))
	assert.Empty(t, rec.Sent(), "email_signup admin: an invited address with no account gets no code")
}

func TestParseProjectConfig_AdmitTenantInvitationsNeedsInviteMode(t *testing.T) {
	for _, mode := range []string{AccessModeOpen, AccessModeClosed} {
		_, err := ParseProjectConfig(`{"access":{"mode":"` + mode + `","admit_tenant_invitations":true}}`)
		require.Error(t, err, mode)
	}
	_, err := ParseProjectConfig(`{"access":{"mode":"allowlist","allowed_domains":["example.com"],"admit_tenant_invitations":true}}`)
	require.Error(t, err)
	cfg, err := ParseProjectConfig(inviteOnlyJSON)
	require.NoError(t, err)
	assert.True(t, cfg.Access.AdmitTenantInvitations)
}

func TestInviteOnly_PasswordSignupIsNotAdmittedByAnInvitation(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	svc.WithOpenInvitations(invitationsWith(pending("new@example.com")))

	_, err := svc.PasswordSignup(accessScope(t, inviteOnlyJSON), "new@example.com", accessTestPassword, "N", "", 0, "", EmailLinkParams{})

	require.ErrorIs(t, err, ErrSignupByInvitationOnly, "a password proves nothing about the mailbox")
	u, _ := repo.FindUserByEmail(context.Background(), "new@example.com")
	assert.Nil(t, u)
}

func TestInviteOnly_ExistingAccountLoginUnchanged(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo).WithOpenInvitations(invitationsWith())
	seedUser(repo, "member@example.com", "", "active")

	require.NoError(t, invitedOAuthSignIn(accessScope(t, inviteOnlyJSON), svc, "member@example.com"))
}

func TestInviteOnly_EmailCodeSentToAndRedeemedByAnInvitedAddress(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.WithOpenInvitations(invitationsWith(pending("new@example.com")))
	ctx := accessScope(t, inviteOnlyJSON)

	require.NoError(t, svc.RequestEmailLoginCode(ctx, "new@example.com"))
	require.Len(t, rec.Sent(), 1, "an invited address gets its sign-in code")
	res, err := svc.VerifyEmailLoginCode(ctx, "new@example.com", extractCodeFromEmail(t, rec.Sent()[0].Text), "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	u, _ := repo.FindUserByEmail(context.Background(), "new@example.com")
	require.NotNil(t, u)

	rec.Reset()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "stranger@example.com"))
	assert.Empty(t, rec.Sent(), "an address with no invitation and no account still gets nothing")
}

func TestInviteOnly_AdmissionIsAuditedAfterTheAccountExists(t *testing.T) {
	repo := newFakeRepo()
	w := newRecordingAuditWriter()
	core, logs := observer.New(zapcore.InfoLevel)
	svc := newTestAuthService(t, repo).WithOpenInvitations(invitationsWith(pending("new@example.com")))
	svc.audit = audit.NewLogger(w, "test-tenant", nil)
	svc.logger = zap.New(core)

	require.NoError(t, invitedOAuthSignIn(accessScope(t, inviteOnlyJSON), svc, "new@example.com"))

	u, _ := repo.FindUserByEmail(context.Background(), "new@example.com")
	require.NotNil(t, u)
	assert.Equal(t, 1, w.countByEventTypeActorTarget(string(audit.EventSignupAdmittedByInvitation), "", u.ID))
	assert.Equal(t, [][2]string{{"203.0.113.9", "invited-test"}}, w.clientsOf(string(audit.EventSignupAdmittedByInvitation)))
	admitted := logs.FilterMessage("signup_admitted_by_tenant_invitation").All()
	require.Len(t, admitted, 1)
	assert.Equal(t, u.ID, admitted[0].ContextMap()["user_id"])
	assert.Equal(t, "example.com", admitted[0].ContextMap()["email_domain"])
	assert.Zero(t, logs.FilterMessage("project_access_denied").Len(), "an admission is not first logged as a refusal")
}

func TestInviteOnly_RefusedSignupIsNotAudited(t *testing.T) {
	w := newRecordingAuditWriter()
	svc := newTestAuthService(t, newFakeRepo()).WithOpenInvitations(invitationsWith())
	svc.audit = audit.NewLogger(w, "test-tenant", nil)

	require.ErrorIs(t, invitedOAuthSignIn(accessScope(t, inviteOnlyJSON), svc, "new@example.com"), ErrSignupByInvitationOnly)
	assert.NotContains(t, w.events, string(audit.EventSignupAdmittedByInvitation))
}

func TestInviteOnly_NoCodeWhilePasswordlessSignupIsOff(t *testing.T) {
	svc, _, rec := newAuthSvcWithMailer(t)
	svc.cfg.PasswordlessSignupEnabled = false
	svc.WithOpenInvitations(invitationsWith(pending("new@example.com")))

	require.NoError(t, svc.RequestEmailLoginCode(accessScope(t, inviteOnlyJSON), "new@example.com"))
	assert.Empty(t, rec.Sent(), "redemption would refuse an unknown address, so no code goes")
}
