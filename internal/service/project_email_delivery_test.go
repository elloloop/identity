package service

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/email"
)

func TestProjectMailTransportUsesCurrentPolicy(t *testing.T) {
	project := &AdminProject{ID: "restricted"}
	projects := &fakeActiveProjects{active: map[string]*AdminProject{
		project.ID: project,
		"ordinary": {ID: "ordinary"},
	}}
	mail := &recordingTransport{}
	transport := NewProjectMailTransport(mail, "ordinary", projects)
	ctx, cancel := context.WithCancel(WithProjectScope(context.Background(), &ProjectScope{ProjectID: project.ID}))
	defer cancel()
	message := email.Message{To: "recipient@example.test", Subject: "Test"}
	require.NoError(t, transport.Send(ctx, message))

	project.EmailDelivery.Disabled = true
	cancel()
	// A queued send carries the project selector even if the request ended.
	require.ErrorIs(t, transport.Send(context.WithoutCancel(ctx), message), ErrEmailDeliveryDisabled)
	require.ErrorIs(t, transport.Send(WithProjectScope(context.Background(), &ProjectScope{ProjectID: "absent"}), message), ErrUnavailable)
	require.NoError(t, transport.Send(context.Background(), message))
	projects.err = ErrServiceUnavailable
	require.ErrorIs(t, transport.Send(context.Background(), message), ErrUnavailable)
	require.Len(t, mail.Sent(), 2)
}

func TestDisabledProjectEmailDoesNotMintCredentials(t *testing.T) {
	svc, repo, mail := passwordlessSvc(t)
	svc.cfg.AuthRequireVerifiedEmail = true
	svc.cfg.PasswordResetEnabled = true
	svc.cfg.PasskeySignupEnabled = true
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "restricted", Access: ProjectAccessConfig{Mode: AccessModeOpen},
		RecoveryEmails: ProjectRecoveryEmailsConfig{Enabled: true},
	})
	svc.WithActiveProjects(&fakeActiveProjects{active: map[string]*AdminProject{
		"restricted": {ID: "restricted", EmailDelivery: ProjectEmailDeliveryConfig{Disabled: true}},
	}})
	const knownAddress = "known@example.test"
	const newAddress = "new@example.test"
	user := seedUser(repo, knownAddress, hashPW(t, strongPW), "active")
	for _, address := range []string{knownAddress, newAddress} {
		require.NoError(t, svc.RequestEmailLoginCode(ctx, address))
		require.NoError(t, svc.RequestMagicLink(ctx, address, "https://app.test/"))
		require.NoError(t, svc.RequestPasswordReset(ctx, address, EmailLinkParams{}))
		_, err := svc.PasswordSignup(ctx, address, strongPW, "", "", nil, "", EmailLinkParams{})
		require.ErrorIs(t, err, ErrEmailDeliveryDisabled)
		_, _, err = svc.BeginPasskeySignup(ctx, address, "device")
		require.ErrorIs(t, err, ErrEmailDeliveryDisabled)
	}
	require.ErrorIs(t, svc.SendEmailVerification(ctx, user.ID, EmailLinkParams{}), ErrEmailDeliveryDisabled)
	require.ErrorIs(t, svc.RequestEmailChange(ctx, user.ID, SessionSignIn{}, newAddress, strongPW), ErrEmailDeliveryDisabled)
	require.ErrorIs(t, svc.RequestRecoveryEmail(ctx, user.ID, SessionSignIn{}, newAddress), ErrEmailDeliveryDisabled)
	opts := svc.HostedUIOptions(ctx, "https://auth.example.test")
	require.True(t, opts.PasswordLoginEnabled)
	require.False(t, opts.PasswordSignupEnabled)
	require.Empty(t, repo.emailLoginCodes)
	require.Empty(t, repo.magicLinkTokens)
	require.Empty(t, repo.passwordResets)
	require.Empty(t, repo.passkeyChallenges)
	require.Empty(t, repo.emailVerifications)
	require.Empty(t, repo.emailChanges)
	require.Empty(t, repo.recoveryEmailCodes)
	require.Len(t, repo.users, 1)
	require.Empty(t, mail.Sent())
}

func TestProjectEmailAsyncDispatchPreservesIsolation(t *testing.T) {
	svc, _, mail := passwordlessSvc(t)
	_, err := svc.WithAsyncEmailDispatch(prometheus.NewRegistry())
	require.NoError(t, err)
	projects := &fakeActiveProjects{active: map[string]*AdminProject{
		"restricted": {ID: "restricted", EmailDelivery: ProjectEmailDeliveryConfig{Disabled: true}},
		"ordinary":   {ID: "ordinary"},
	}}
	svc.WithActiveProjects(projects)
	svc.mailer = NewProjectMailTransport(mail, svc.cfg.DefaultProjectID, projects)
	for _, id := range []string{"restricted", "ordinary"} {
		ctx, cancel := context.WithCancel(WithProjectScope(context.Background(), &ProjectScope{
			ProjectID: id, Access: ProjectAccessConfig{Mode: AccessModeOpen},
		}))
		require.NoError(t, svc.RequestEmailLoginCode(ctx, id+"@example.test"))
		cancel()
	}
	require.Eventually(t, func() bool { return len(svc.emailSendSlots) == 0 }, time.Second, time.Millisecond)
	sent := mail.Sent()
	require.Len(t, sent, 1)
	require.Equal(t, "ordinary@example.test", sent[0].To)
}

func TestParseProjectEmailDeliveryConfig(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		disabled bool
	}{
		{`{}`, false},
		{`{"email_delivery":{"disabled":false}}`, false},
		{`{"email_delivery":{"disabled":true}}`, true},
	} {
		cfg, err := ParseProjectConfig(tc.raw)
		require.NoError(t, err)
		require.Equal(t, tc.disabled, cfg.EmailDelivery.Disabled)
	}
	_, err := ParseProjectConfig(`{"email_delivery":{"disabled":"true"}}`)
	require.Error(t, err)
}
