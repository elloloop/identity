package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/sms"
)

// fakePhoneSender records each SMS so the handler test can read back the
// delivered code.
type fakePhoneSender struct {
	mu       sync.Mutex
	messages []sms.Message
}

func (f *fakePhoneSender) Send(_ context.Context, m sms.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, m)
	return nil
}

func (f *fakePhoneSender) lastBody() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.messages) == 0 {
		return ""
	}
	return f.messages[len(f.messages)-1].Body
}

// newPhoneHarness builds a harness with SMS enabled and the supplied
// fake sender so the phone-verification handlers are exercised end to
// end through the Connect transport.
func newPhoneHarness(t *testing.T, sender sms.Sender) *testHarness {
	t.Helper()

	repo := newFakeRepo()
	db := newFakeDB()
	cfg := testConfig()
	cfg.SMSEnabled = true
	cfg.SMSProvider = "twilio"
	cfg.PhoneCodeTTLSeconds = 300
	cfg.PhoneCodeMaxAttempts = 5
	cfg.PhoneCodeCooldownSeconds = 60
	kr := testKeyRing(t)

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	require.NoError(t, err)

	auditLog := audit.NewLogger(nil, "test", zap.NewNop())
	totpKey := []byte("01234567890123456789012345678901")
	totpRecoveryPepper := []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH")

	authSvc := service.NewAuthServiceWithOAuth(repo, cfg, kr, pkSvc, auditLog, totpKey, totpRecoveryPepper, nil, sender, zap.NewNop(), nil)
	adminSvc := service.NewAdminService(repo, db, cfg.DefaultTenantID, auditLog, cfg, nil, zap.NewNop())
	groupSvc := service.NewGroupService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())
	helpSvc := service.NewHelpService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())
	profSvc := service.NewProfileService(repo, db, cfg.DefaultTenantID, auditLog, zap.NewNop())

	h := NewIdentityHandler(authSvc, adminSvc, groupSvc, helpSvc, profSvc, nil, nil, nil, nil, cfg)

	mux := http.NewServeMux()
	path, handler := identityconnect.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testHarness{
		repo:   repo,
		db:     db,
		auth:   authSvc,
		admin:  adminSvc,
		groups: groupSvc,
		help:   helpSvc,
		prof:   profSvc,
		cfg:    cfg,
		server: srv,
		client: identityconnect.NewIdentityServiceClient(srv.Client(), srv.URL),
	}
}

func seedHandlerUser(t *testing.T, h *testHarness, email string) string {
	t.Helper()
	id, err := h.repo.CreateUser(context.Background(), &service.User{Email: email, Status: "active", Role: "member"})
	require.NoError(t, err)
	return id
}

// codeFromBody extracts the 6-digit OTP from the SMS body.
func codeFromBody(t *testing.T, body string) string {
	t.Helper()
	const prefix = "Your verification code is "
	i := -1
	for j := 0; j+len(prefix) <= len(body); j++ {
		if body[j:j+len(prefix)] == prefix {
			i = j
			break
		}
	}
	require.GreaterOrEqual(t, i, 0, "body has no code prefix: %q", body)
	rest := body[i+len(prefix):]
	require.GreaterOrEqual(t, len(rest), 6)
	return rest[:6]
}

func TestHandler_RequestPhoneVerification_Unauthenticated(t *testing.T) {
	h := newPhoneHarness(t, &fakePhoneSender{})
	// No X-Authenticated-User-Id header → Unauthenticated.
	_, err := h.client.RequestPhoneVerification(context.Background(),
		connect.NewRequest(&identitypb.RequestPhoneVerificationRequest{PhoneNumber: "+14155550123"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestHandler_VerifyPhoneCode_Unauthenticated(t *testing.T) {
	h := newPhoneHarness(t, &fakePhoneSender{})
	_, err := h.client.VerifyPhoneCode(context.Background(),
		connect.NewRequest(&identitypb.VerifyPhoneCodeRequest{PhoneNumber: "+14155550123", Code: "123456"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestHandler_PhoneVerification_HappyPath(t *testing.T) {
	sender := &fakePhoneSender{}
	h := newPhoneHarness(t, sender)
	uid := seedHandlerUser(t, h, "ph@test.com")

	_, err := h.client.RequestPhoneVerification(context.Background(),
		authedReq(connect.NewRequest(&identitypb.RequestPhoneVerificationRequest{PhoneNumber: "+14155550123"}), uid))
	require.NoError(t, err)

	code := codeFromBody(t, sender.lastBody())

	resp, err := h.client.VerifyPhoneCode(context.Background(),
		authedReq(connect.NewRequest(&identitypb.VerifyPhoneCodeRequest{
			PhoneNumber: "+14155550123", Code: code,
		}), uid))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.User)
	assert.True(t, resp.Msg.User.PhoneVerified)
	assert.Equal(t, "+14155550123", resp.Msg.User.PhoneNumber)
}

func TestHandler_VerifyPhoneCode_WrongCodeUnauthenticated(t *testing.T) {
	sender := &fakePhoneSender{}
	h := newPhoneHarness(t, sender)
	uid := seedHandlerUser(t, h, "ph-wrong@test.com")

	_, err := h.client.RequestPhoneVerification(context.Background(),
		authedReq(connect.NewRequest(&identitypb.RequestPhoneVerificationRequest{PhoneNumber: "+14155550123"}), uid))
	require.NoError(t, err)

	_, err = h.client.VerifyPhoneCode(context.Background(),
		authedReq(connect.NewRequest(&identitypb.VerifyPhoneCodeRequest{
			PhoneNumber: "+14155550123", Code: "000000",
		}), uid))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestHandler_RequestPhoneVerification_SMSDisabledUnavailable(t *testing.T) {
	// A default harness has SMS disabled; the handler should surface
	// CodeUnavailable.
	h := newHarness(t)
	uid := seedHandlerUser(t, h, "ph-disabled@test.com")
	_, err := h.client.RequestPhoneVerification(context.Background(),
		authedReq(connect.NewRequest(&identitypb.RequestPhoneVerificationRequest{PhoneNumber: "+14155550123"}), uid))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
}
