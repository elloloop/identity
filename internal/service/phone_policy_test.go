package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/templatemsg"
)

// fakeTemplateSender records each template message. An optional err makes
// Send fail.
type fakeTemplateSender struct {
	mu       sync.Mutex
	messages []templatemsg.Message
	err      error
}

func (f *fakeTemplateSender) Send(_ context.Context, m templatemsg.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.messages = append(f.messages, m)
	return nil
}

func (f *fakeTemplateSender) sent() []templatemsg.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]templatemsg.Message(nil), f.messages...)
}

// phoneFixture is a phone-verifying AuthService in a project with the
// given phone policy.
type phoneFixture struct {
	svc    *AuthService
	repo   *fakeRepo
	sms    *fakeSMSSender
	mailer *recordingMailer
	now    time.Time
	ctx    context.Context
}

func newPhoneFixture(t *testing.T, cfg ProjectPhoneConfig) *phoneFixture {
	t.Helper()
	f := &phoneFixture{repo: newFakeRepo(), sms: &fakeSMSSender{}, mailer: &recordingMailer{}, now: time.Unix(1_800_000_000, 0)}
	f.svc = newTestPhoneService(t, f.repo, f.sms)
	f.svc.mailer = f.mailer
	f.svc.nowFunc = func() time.Time { return f.now }
	f.ctx = WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-a", Phone: cfg})
	return f
}

// verify runs both steps for userID and number, reading the code from the
// SMS, and returns VerifyPhoneCode's answer.
func (f *phoneFixture) verify(t *testing.T, userID, number string) (*User, error) {
	t.Helper()
	before := f.sms.count()
	require.NoError(t, f.svc.RequestPhoneVerification(f.ctx, userID, SessionSignIn{}, number))
	require.Equal(t, before+1, f.sms.count(), "a code is sent whether or not the number is taken")
	msg, _ := f.sms.last()
	user, err := f.svc.VerifyPhoneCode(f.ctx, userID, SessionSignIn{}, number, extractCode(t, msg.Body))
	// Past the per-user send cooldown, for the next request in the test.
	f.now = f.now.Add(2 * time.Minute)
	return user, err
}

func off() *bool { v := false; return &v }

func TestPhone_AProjectCanSwitchVerificationOff(t *testing.T) {
	f := newPhoneFixture(t, ProjectPhoneConfig{Enabled: off()})
	id := seedPhoneUser(t, f.repo, "owner@example.com")

	require.ErrorIs(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"), ErrSMSDisabled)
	_, err := f.svc.VerifyPhoneCode(f.ctx, id, SessionSignIn{}, "+14155550123", "123456")
	require.ErrorIs(t, err, ErrSMSDisabled)
	assert.Zero(t, f.sms.count())

	// Another project of the same deployment, with no phone block, is as on
	// as the deployment is.
	other := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-b"})
	require.NoError(t, f.svc.RequestPhoneVerification(other, id, SessionSignIn{}, "+14155550123"))
	assert.Equal(t, 1, f.sms.count())
}

func TestPhone_OnlyTheProjectsCountriesAreSentACode(t *testing.T) {
	f := newPhoneFixture(t, ProjectPhoneConfig{AllowedCallingCodes: []string{"91", "44"}})
	id := seedPhoneUser(t, f.repo, "owner@example.com")

	require.ErrorIs(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"), ErrPhoneCountryNotAllowed)
	_, err := f.svc.VerifyPhoneCode(f.ctx, id, SessionSignIn{}, "+14155550123", "123456")
	require.ErrorIs(t, err, ErrPhoneCountryNotAllowed)
	assert.Zero(t, f.sms.count(), "a refused country costs no message")

	user, err := f.verify(t, id, "+919876543210")
	require.NoError(t, err)
	assert.Equal(t, "+919876543210", user.PhoneNumber)
}

func TestPhone_ChannelsAreTriedInTheProjectsOrder(t *testing.T) {
	policy := ProjectPhoneConfig{
		Channels:        []string{PhoneChannelMessage, PhoneChannelSMS},
		MessageTemplate: "verification_code", MessageLanguage: "en",
	}

	t.Run("the message channel goes first and SMS is not used", func(t *testing.T) {
		f := newPhoneFixture(t, policy)
		tmpl := &fakeTemplateSender{}
		f.svc.WithTemplateMessages(tmpl)
		id := seedPhoneUser(t, f.repo, "owner@example.com")

		require.NoError(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"))
		sent := tmpl.sent()
		require.Len(t, sent, 1)
		assert.Equal(t, "+14155550123", sent[0].To)
		assert.Equal(t, "verification_code", sent[0].Template)
		assert.Equal(t, "en", sent[0].Language)
		require.Len(t, sent[0].Params, 1)
		assert.Zero(t, f.sms.count())

		user, err := f.svc.VerifyPhoneCode(f.ctx, id, SessionSignIn{}, "+14155550123", sent[0].Params[0])
		require.NoError(t, err)
		assert.True(t, user.PhoneVerified)
	})

	t.Run("a message the provider refuses falls back to SMS", func(t *testing.T) {
		f := newPhoneFixture(t, policy)
		f.svc.WithTemplateMessages(&fakeTemplateSender{err: templatemsg.ErrTransport})
		id := seedPhoneUser(t, f.repo, "owner@example.com")
		require.NoError(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"))
		assert.Equal(t, 1, f.sms.count())
	})

	t.Run("with no template sender the channel is skipped", func(t *testing.T) {
		f := newPhoneFixture(t, policy)
		id := seedPhoneUser(t, f.repo, "owner@example.com")
		require.NoError(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"))
		assert.Equal(t, 1, f.sms.count())
	})

	t.Run("a channel the project leaves out is never used", func(t *testing.T) {
		messageOnly := policy
		messageOnly.Channels = []string{PhoneChannelMessage}
		f := newPhoneFixture(t, messageOnly)
		id := seedPhoneUser(t, f.repo, "owner@example.com")

		// No template sender: the project has no usable channel, though the
		// deployment could text.
		require.ErrorIs(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"), ErrSMSDisabled)
		// A failing sender surfaces, and SMS is still not used.
		f.svc.WithTemplateMessages(&fakeTemplateSender{err: templatemsg.ErrTransport})
		err := f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123")
		require.ErrorIs(t, err, ErrSMSDisabled)
		require.ErrorIs(t, err, templatemsg.ErrTransport)
		assert.Zero(t, f.sms.count())
	})

	t.Run("the message channel works in a deployment with no SMS provider", func(t *testing.T) {
		messageOnly := policy
		messageOnly.Channels = []string{PhoneChannelMessage}
		f := newPhoneFixture(t, messageOnly)
		f.svc.cfg.SMSEnabled = false
		tmpl := &fakeTemplateSender{}
		f.svc.WithTemplateMessages(tmpl)
		id := seedPhoneUser(t, f.repo, "owner@example.com")
		require.NoError(t, f.svc.RequestPhoneVerification(f.ctx, id, SessionSignIn{}, "+14155550123"))
		assert.Len(t, tmpl.sent(), 1)
	})
}

func TestPhone_UniqueNumberBelongsToOneAccount(t *testing.T) {
	f := newPhoneFixture(t, ProjectPhoneConfig{Unique: true})
	a := seedPhoneUser(t, f.repo, "a@example.com")
	b := seedPhoneUser(t, f.repo, "b@example.com")
	const number = "+14155550123"

	_, err := f.verify(t, a, number)
	require.NoError(t, err)

	// The second account is sent a code like anyone, and told the number is
	// taken only once its code is right.
	_, err = f.verify(t, b, number)
	require.ErrorIs(t, err, ErrPhoneNumberTaken)
	got, _ := f.repo.GetUser(f.ctx, b)
	assert.Empty(t, got.PhoneNumber)
	assert.False(t, got.PhoneVerified)

	// Released by its holder, the number is free.
	removed, err := f.svc.RemovePhone(f.ctx, a, SessionSignIn{})
	require.NoError(t, err)
	assert.Empty(t, removed.PhoneNumber)
	assert.False(t, removed.PhoneVerified)
	user, err := f.verify(t, b, number)
	require.NoError(t, err)
	assert.Equal(t, number, user.PhoneNumber)
}

func TestPhone_WithoutUniqueANumberMaySitOnTwoAccounts(t *testing.T) {
	f := newPhoneFixture(t, ProjectPhoneConfig{})
	const number = "+14155550123"
	for _, addr := range []string{"a@example.com", "b@example.com"} {
		user, err := f.verify(t, seedPhoneUser(t, f.repo, addr), number)
		require.NoError(t, err)
		assert.Equal(t, number, user.PhoneNumber)
	}
}

func TestPhone_UniqueNumberMovesAfterTheReassignPeriod(t *testing.T) {
	f := newPhoneFixture(t, ProjectPhoneConfig{Unique: true, ReassignAfterSeconds: 3600})
	a := seedPhoneUser(t, f.repo, "a@example.com")
	b := seedPhoneUser(t, f.repo, "b@example.com")
	const number = "+14155550123"

	claimedAt := f.now
	_, err := f.verify(t, a, number)
	require.NoError(t, err)

	f.now = claimedAt.Add(time.Hour - time.Second)
	_, err = f.verify(t, b, number)
	require.ErrorIs(t, err, ErrPhoneNumberTaken, "a second short of the period")

	// The refused attempt left the clock past the period (and past the send
	// cooldown).
	require.False(t, f.now.Before(claimedAt.Add(time.Hour)))
	user, err := f.verify(t, b, number)
	require.NoError(t, err)
	assert.Equal(t, number, user.PhoneNumber)

	previous, _ := f.repo.GetUser(f.ctx, a)
	assert.Empty(t, previous.PhoneNumber, "the previous holder loses the number")
	assert.False(t, previous.PhoneVerified)
	require.Equal(t, 1, f.mailer.count(), "the previous holder is told")
	notice := f.mailer.last()
	assert.Equal(t, "a@example.com", notice.To)
	assert.Equal(t, "Your phone number was removed from your account", notice.Subject)
	assert.NotContains(t, notice.Text, number, "the notice carries the number redacted")
}

func TestPhone_RemoveTellsTheAccountAndRespectsTheHold(t *testing.T) {
	f := newPhoneFixture(t, ProjectPhoneConfig{})
	id := seedPhoneUser(t, f.repo, "owner@example.com")

	// Nothing to remove is not an error.
	user, err := f.svc.RemovePhone(f.ctx, id, SessionSignIn{})
	require.NoError(t, err)
	assert.Empty(t, user.PhoneNumber)
	assert.Zero(t, f.mailer.count())

	_, err = f.verify(t, id, "+14155550123")
	require.NoError(t, err)

	// A sign-in by a recovery email holds the phone as it holds the emails,
	// for the session that sign-in opened.
	require.NoError(t, f.repo.AddRecoveryEmail(f.ctx, &RecoveryEmail{UserID: id, Email: "spare@example.net", VerifiedAt: 1}, 5))
	require.NoError(t, f.repo.MarkRecoveryEmailSignIn(f.ctx, id, "spare@example.net", f.now.UnixMilli(), (7*24*time.Hour).Milliseconds()))
	_, err = f.svc.RemovePhone(f.ctx, id, SessionSignIn{AMR: []string{AMRRecoveryEmail}})
	require.ErrorIs(t, err, ErrRecoveryHold)

	f.now = f.now.Add(7 * 24 * time.Hour)
	// The project switching verification off does not strand a stored number.
	scope := *ProjectScopeFromContext(f.ctx)
	scope.Phone.Enabled = off()
	user, err = f.svc.RemovePhone(WithProjectScope(context.Background(), &scope), id, SessionSignIn{})
	require.NoError(t, err)
	assert.Empty(t, user.PhoneNumber)
	assert.False(t, user.PhoneVerified)
	assert.Zero(t, user.PhoneVerifiedAt)
	assert.Equal(t, 2, f.mailer.count(), "the primary and the recovery email are told")
	assert.Equal(t, "The phone number was removed from your account", f.mailer.last().Subject)

	_, err = f.svc.RemovePhone(f.ctx, "", SessionSignIn{})
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = f.svc.RemovePhone(f.ctx, "no-such-user", SessionSignIn{})
	require.ErrorIs(t, err, ErrNotFound)
}

func TestProjectPhoneConfig_Validate(t *testing.T) {
	valid := []ProjectPhoneConfig{
		{},
		{Enabled: off()},
		{Unique: true, ReassignAfterSeconds: 86400},
		{AllowedCallingCodes: []string{"1", "44", "971"}},
		{Channels: []string{PhoneChannelSMS}},
		{Channels: []string{PhoneChannelMessage, PhoneChannelSMS}, MessageTemplate: "code", MessageLanguage: "en_GB"},
	}
	for _, c := range valid {
		require.NoError(t, ProjectConfig{Phone: c}.Validate(), "%+v", c)
	}
	invalid := map[string]ProjectPhoneConfig{
		"negative period":            {Unique: true, ReassignAfterSeconds: -1},
		"period without unique":      {ReassignAfterSeconds: 60},
		"calling code with a plus":   {AllowedCallingCodes: []string{"+91"}},
		"calling code too long":      {AllowedCallingCodes: []string{"1242"}},
		"calling code leading zero":  {AllowedCallingCodes: []string{"044"}},
		"empty calling code":         {AllowedCallingCodes: []string{""}},
		"calling code listed twice":  {AllowedCallingCodes: []string{"91", "91"}},
		"unknown channel":            {Channels: []string{"carrier-pigeon"}},
		"channel listed twice":       {Channels: []string{PhoneChannelSMS, PhoneChannelSMS}},
		"message channel no name":    {Channels: []string{PhoneChannelMessage}},
		"template with a space edge": {MessageTemplate: " code"},
	}
	for name, c := range invalid {
		err := ProjectConfig{Phone: c}.Validate()
		require.ErrorIs(t, err, ErrInvalidArgument, name)
	}

	parsed, err := ParseProjectConfig(`{"phone":{"enabled":false,"unique":true,"reassign_after_seconds":60,
		"allowed_calling_codes":["91"],"channels":["message","sms"],"message_template":"code","message_language":"en"}}`)
	require.NoError(t, err)
	require.NotNil(t, parsed.Phone.Enabled)
	assert.False(t, *parsed.Phone.Enabled)
	assert.True(t, parsed.Phone.off())
	assert.Equal(t, []string{"message", "sms"}, parsed.Phone.channels())
	assert.Equal(t, []string{PhoneChannelSMS}, ProjectPhoneConfig{}.channels())
	assert.False(t, ProjectPhoneConfig{}.off())
}

func TestHasCallingCode(t *testing.T) {
	assert.True(t, hasCallingCode("+919876543210", nil), "no list accepts every country")
	assert.True(t, hasCallingCode("+919876543210", []string{"44", "91"}))
	assert.False(t, hasCallingCode("+14155550123", []string{"44", "91"}))
	assert.False(t, hasCallingCode("+9", []string{"91"}))
}

// A tenant whose login policy requires a verified phone admits no session
// of an account without one: no token for the tenant is minted, the refresh
// token is left unspent, and the unselected session it leaves is what the
// account verifies a phone with.
func TestRefreshToken_SelectionNeedsTheVerifiedPhoneTheTenantRequires(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policy   *LoginPolicy
		phone    string
		verified bool
		admitted bool
	}{
		{name: "required, no phone", policy: &LoginPolicy{RequireVerifiedPhone: true}},
		{name: "required, number stored but unverified", policy: &LoginPolicy{RequireVerifiedPhone: true}, phone: "+14155550123"},
		{name: "required, verified", policy: &LoginPolicy{RequireVerifiedPhone: true}, phone: "+14155550123", verified: true, admitted: true},
		{name: "required of one country, verified in another", policy: &LoginPolicy{RequireVerifiedPhone: true, PhoneCallingCodes: "91,44"}, phone: "+14155550123", verified: true},
		{name: "required of one country, verified there", policy: &LoginPolicy{RequireVerifiedPhone: true, PhoneCallingCodes: "91,44"}, phone: "+447700900123", verified: true, admitted: true},
		{name: "not required, no phone", policy: &LoginPolicy{SessionAbsoluteTimeoutSeconds: 3600}, admitted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSelectionFixture(t)
			f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusActive)
			f.governTenant("t-acme", "acme.example.test", tc.policy)
			if tc.phone != "" {
				f.repo.mu.Lock()
				f.repo.users[f.user.ID].PhoneNumber = tc.phone
				f.repo.users[f.user.ID].PhoneVerified = tc.verified
				f.repo.mu.Unlock()
			}

			_, access, _, err := f.svc.RefreshToken(context.Background(), f.refresh, "t-acme", "", "")
			if tc.admitted {
				require.NoError(t, err)
				assert.Equal(t, "t-acme", f.tenantClaim(t, access))
				return
			}
			require.ErrorIs(t, err, ErrPhoneVerificationRequired)
			requireSelectionRefusal(t, err, TenantSelectionPhoneRequired)
			_, access, _, err = f.svc.RefreshToken(context.Background(), f.refresh, "", "", "")
			require.NoError(t, err, "the refused selection left the refresh token unspent")
			assert.Equal(t, f.svc.cfg.DefaultTenantID, f.tenantClaim(t, access))
		})
	}
}

// A session past the tenant's timeout is refused for that, not sent to
// verify a phone it would be refused with anyway.
func TestRefreshToken_LoginPolicyRefusalComesBeforeThePhoneRule(t *testing.T) {
	f := newSelectionFixture(t)
	f.seedTenant(t, "t-acme", TenantStatusClaimed, MembershipStatusActive)
	f.governTenant("t-acme", "acme.example.test", &LoginPolicy{RequireVerifiedPhone: true, SessionAbsoluteTimeoutSeconds: 60})
	later := time.Now().Add(2 * time.Minute)
	f.svc.nowFunc = func() time.Time { return later }

	_, _, _, err := f.svc.RefreshToken(context.Background(), f.refresh, "t-acme", "", "")
	requireSelectionRefusal(t, err, TenantSelectionLoginPolicy)
}

func TestUpsertLoginPolicy_PhoneRule(t *testing.T) {
	f := newAdminFixture(policyAdminSecret)
	ctx := context.Background()

	got, err := f.svc.UpsertLoginPolicy(ctx, policyAdminSecret, &LoginPolicy{
		ProjectID: "proj-1", TenantID: "tenant-1", RequireVerifiedPhone: true, PhoneCallingCodes: "91, 44 ,",
	})
	require.NoError(t, err)
	assert.True(t, got.RequireVerifiedPhone)
	assert.Equal(t, "91,44", got.PhoneCallingCodes)
	read, err := f.svc.GetLoginPolicy(ctx, asAdmin(policyAdminSecret), "proj-1", "tenant-1")
	require.NoError(t, err)
	assert.True(t, read.RequireVerifiedPhone)
	assert.Equal(t, "91,44", read.PhoneCallingCodes)

	for name, bad := range map[string]*LoginPolicy{
		"codes without the requirement": {PhoneCallingCodes: "91"},
		"a plus":                        {RequireVerifiedPhone: true, PhoneCallingCodes: "+91"},
		"letters":                       {RequireVerifiedPhone: true, PhoneCallingCodes: "abc"},
		"listed twice":                  {RequireVerifiedPhone: true, PhoneCallingCodes: "91,91"},
		"four digits":                   {RequireVerifiedPhone: true, PhoneCallingCodes: "1234"},
	} {
		bad.ProjectID, bad.TenantID = "proj-1", "tenant-1"
		_, err := f.svc.UpsertLoginPolicy(ctx, policyAdminSecret, bad)
		require.ErrorIs(t, err, ErrInvalidArgument, name)
	}
	// The requirement is not a permission refusal: the account may act in
	// the tenant once it has a phone.
	assert.False(t, errors.Is(ErrPhoneVerificationRequired, ErrPermissionDenied))
}
