package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/sms"
)

// captureFixture is a phone fixture whose deployment captures the channels
// capture names, logging into logs.
type captureFixture struct {
	*phoneFixture
	transport *recordingTransport
	tmpl      *fakeTemplateSender
	logs      *observer.ObservedLogs
}

func newCaptureFixture(t *testing.T, policy ProjectPhoneConfig, captureSMS, captureMessages bool) *captureFixture {
	t.Helper()
	f := &captureFixture{phoneFixture: newPhoneFixture(t, policy), transport: &recordingTransport{}, tmpl: &fakeTemplateSender{}}
	if captureSMS {
		f.svc.cfg.SMSProvider = config.SMSProviderLocalCapture
	}
	if captureMessages {
		f.svc.cfg.TemplateMessageProvider = config.TemplateMessageProviderLocalCapture
	}
	core, logs := observer.New(zapcore.DebugLevel)
	f.logs = logs
	f.svc.logger = zap.New(core)
	f.svc.mailer = f.transport
	f.svc.WithTemplateMessages(f.tmpl)
	return f
}

// assertNoLineCarries fails when any log line's message or fields carry
// one of secrets.
func assertNoLineCarries(t *testing.T, logs *observer.ObservedLogs, secrets ...string) {
	t.Helper()
	for _, entry := range logs.All() {
		lines := []string{entry.Message}
		for k, v := range entry.ContextMap() {
			lines = append(lines, k+"="+fmt.Sprint(v))
		}
		for _, line := range lines {
			for _, secret := range secrets {
				if strings.Contains(line, secret) {
					t.Errorf("log line %q carries %q", entry.Message, secret)
				}
			}
		}
	}
}

func TestPhoneCapture_ACodeIsMailedToTheAccountAndVerifies(t *testing.T) {
	const number = "+14155550123"
	cases := []struct {
		name                        string
		policy                      ProjectPhoneConfig
		captureSMS, captureMessages bool
		wantChannel                 string
	}{
		{name: "SMS", captureSMS: true, wantChannel: "SMS"},
		{
			name: "the message channel, ahead of the embedder's sender",
			policy: ProjectPhoneConfig{
				Channels: []string{PhoneChannelMessage}, MessageTemplate: "verification_code", MessageLanguage: "en",
			},
			captureMessages: true, wantChannel: "a messaging-app message",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCaptureFixture(t, tc.policy, tc.captureSMS, tc.captureMessages)
			id := seedPhoneUser(t, f.repo, "owner@example.com")

			require.NoError(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, number))
			assert.Zero(t, f.sms.count(), "a captured code is not texted")
			assert.Empty(t, f.tmpl.sent(), "a captured code is not sent as a template message")
			sent := f.transport.Sent()
			require.Len(t, sent, 1)
			assert.Equal(t, "owner@example.com", sent[0].To)
			assert.Equal(t, "Your phone verification code", sent[0].Subject)
			assert.Contains(t, sent[0].Text, sms.Redact(number))
			assert.Contains(t, sent[0].Text, tc.wantChannel)
			assert.NotContains(t, sent[0].Text, number, "the email names the number redacted")
			code := extractCodeFromEmail(t, sent[0].Text)
			assert.Contains(t, sent[0].HTML, code)

			user, err := f.svc.VerifyPhoneCode(f.ctx, id, SessionSignIn{}, number, code)
			require.NoError(t, err)
			assert.True(t, user.PhoneVerified)
			assert.Equal(t, number, user.PhoneNumber)

			assertNoLineCarries(t, f.logs, code, number)
		})
	}
}

// Capture makes the message channel usable on a deployment with no template
// sender, as a provider would.
func TestPhoneCapture_TurnsOnTheMessageChannelWithoutASender(t *testing.T) {
	policy := ProjectPhoneConfig{Channels: []string{PhoneChannelMessage}, MessageTemplate: "verification_code"}
	f := newCaptureFixture(t, policy, false, false)
	f.svc.WithTemplateMessages(nil)
	id := seedPhoneUser(t, f.repo, "owner@example.com")
	require.ErrorIs(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"), ErrPhoneVerificationUnavailable)

	f.svc.cfg.TemplateMessageProvider = config.TemplateMessageProviderLocalCapture
	require.NoError(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"))
	assert.Len(t, f.transport.Sent(), 1)
}

func TestPhoneCapture_ACodeThatCannotBeMailedMovesOnToTheNextChannel(t *testing.T) {
	policy := ProjectPhoneConfig{Channels: []string{PhoneChannelMessage, PhoneChannelSMS}, MessageTemplate: "verification_code"}
	cases := []struct {
		name  string
		email string
		fail  error
	}{
		{name: "an account with no email", email: ""},
		{name: "a mailer that refuses the send", email: "owner@example.com", fail: errors.New("smtp: connection refused")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCaptureFixture(t, policy, false, true)
			f.transport.fail = tc.fail
			id, err := f.repo.CreateUser(f.ctx, &User{Email: tc.email, Username: "owner", Status: "active", Role: "member"})
			require.NoError(t, err)

			require.NoError(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"))
			assert.Equal(t, 1, f.sms.count(), "the SMS channel takes the code")
			msg, _ := f.sms.last()
			assertNoLineCarries(t, f.logs, extractCode(t, msg.Body))

			failed := f.logs.FilterMessage("phone_verification_send_failed").All()
			require.Len(t, failed, 1)
			assert.Equal(t, PhoneChannelMessage, failed[0].ContextMap()["channel"])
		})
	}

	t.Run("with no channel left the request fails", func(t *testing.T) {
		f := newCaptureFixture(t, ProjectPhoneConfig{}, true, false)
		f.transport.fail = errors.New("smtp: connection refused")
		id := seedPhoneUser(t, f.repo, "owner@example.com")
		require.ErrorIs(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"), ErrPhoneVerificationUnavailable)
	})
}

func TestWarnPhoneCodeCapture(t *testing.T) {
	cases := []struct {
		name         string
		cfg          config.Config
		wantChannels []any
	}{
		{name: "no capture", cfg: config.Config{SMSEnabled: true, SMSProvider: config.SMSProviderTwilio}},
		{name: "a capture name on a switched-off SMS channel", cfg: config.Config{SMSProvider: config.SMSProviderLocalCapture}},
		{
			name:         "SMS",
			cfg:          config.Config{SMSEnabled: true, SMSProvider: config.SMSProviderLocalCapture},
			wantChannels: []any{PhoneChannelSMS},
		},
		{
			name: "both channels",
			cfg: config.Config{
				SMSEnabled: true, SMSProvider: config.SMSProviderLocalCapture,
				TemplateMessageProvider: config.TemplateMessageProviderLocalCapture,
			},
			wantChannels: []any{PhoneChannelSMS, PhoneChannelMessage},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.WarnLevel)
			warnPhoneCodeCapture(&tc.cfg, zap.New(core))
			lines := logs.FilterMessage("phone_codes_captured_to_email").All()
			if tc.wantChannels == nil {
				assert.Empty(t, lines)
				return
			}
			require.Len(t, lines, 1)
			assert.Equal(t, zapcore.WarnLevel, lines[0].Level)
			assert.Equal(t, tc.wantChannels, lines[0].ContextMap()["channels"])
		})
	}
}
