package connect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/passkeys"
)

// recordingTransport keeps every message the service mails.
type recordingTransport struct {
	mu   sync.Mutex
	sent []email.Message
}

func (r *recordingTransport) Send(_ context.Context, m email.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, m)
	return nil
}

var mailedCode = regexp.MustCompile(`\b\d{6}\b`)

// codeTo returns the code in the last message mailed to addr.
func (r *recordingTransport) codeTo(t *testing.T, addr string) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.sent) - 1; i >= 0; i-- {
		if r.sent[i].To == addr {
			if code := mailedCode.FindString(r.sent[i].Text); code != "" {
				return code
			}
		}
	}
	t.Fatalf("no code was mailed to %s", addr)
	return ""
}

// newRecoveryEmailHarness serves the handlers in a project with the given
// recovery-email policy, mailing through the returned transport.
func newRecoveryEmailHarness(t *testing.T, policy service.ProjectRecoveryEmailsConfig) (*testHarness, *recordingTransport) {
	t.Helper()
	repo := newFakeRepo()
	db := newFakeDB()
	cfg := testConfig()
	cfg.SMSEnabled = true
	kr := testKeyRing(t)
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin})
	require.NoError(t, err)
	auditLog := audit.NewLogger(nil, "test", zap.NewNop())
	mailer := &recordingTransport{}
	authSvc := service.NewAuthServiceWithOAuth(repo, cfg, kr, pkSvc, auditLog,
		[]byte("01234567890123456789012345678901"), []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		mailer, &fakePhoneSender{}, zap.NewNop(), nil)
	adminSvc := service.NewAdminService(repo, db, cfg.DefaultTenantID, auditLog, cfg, nil, zap.NewNop())
	h := NewIdentityHandler(authSvc, adminSvc,
		service.NewGroupService(db, cfg.DefaultTenantID, auditLog, zap.NewNop()),
		service.NewHelpService(db, cfg.DefaultTenantID, auditLog, zap.NewNop()),
		service.NewProfileService(repo, db, cfg.DefaultTenantID, auditLog, zap.NewNop()),
		nil, nil, nil, nil, nil, cfg)

	mux := http.NewServeMux()
	path, handler := identityconnect.NewIdentityServiceHandler(h)
	scope := &service.ProjectScope{
		ProjectID:      "project-a",
		Access:         service.ProjectAccessConfig{Mode: service.AccessModeOpen},
		RecoveryEmails: policy,
	}
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(service.WithProjectScope(r.Context(), scope)))
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &testHarness{
		repo: repo, db: db, auth: authSvc, admin: adminSvc, cfg: cfg, server: srv,
		client: identityconnect.NewIdentityServiceClient(srv.Client(), srv.URL),
	}, mailer
}

// signedIn marks a request as coming from userID's session, signed in now.
func signedIn[T any](r *connect.Request[T], userID string) *connect.Request[T] {
	r.Header().Set(middleware.AuthenticatedAuthTimeHeader, strconv.FormatInt(time.Now().Unix(), 10))
	return authedReq(r, userID)
}

// tokenAMR reads the amr claim of a token the harness minted. The signature
// is the server's business; this only looks at what the token says.
func tokenAMR(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		AMR []string `json:"amr"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims.AMR
}

// signedInByRecoveryEmail marks a request as coming from a session of
// userID's that a recovery email opened just now.
func signedInByRecoveryEmail[T any](r *connect.Request[T], userID string) *connect.Request[T] {
	r.Header().Set(middleware.AuthenticatedAMRHeader, service.AMRRecoveryEmail)
	return signedIn(r, userID)
}

func TestHandler_RecoveryEmails_AddListRemove(t *testing.T) {
	h, mailer := newRecoveryEmailHarness(t, service.ProjectRecoveryEmailsConfig{Enabled: true})
	ctx := context.Background()
	uid := seedHandlerUser(t, h, "owner@example.com")

	_, err := h.client.RequestRecoveryEmail(ctx,
		signedIn(connect.NewRequest(&identitypb.RequestRecoveryEmailRequest{Email: "spare@example.net"}), uid))
	require.NoError(t, err)

	added, err := h.client.VerifyRecoveryEmail(ctx, signedIn(connect.NewRequest(&identitypb.VerifyRecoveryEmailRequest{
		Email: "spare@example.net", Code: mailer.codeTo(t, "spare@example.net"),
	}), uid))
	require.NoError(t, err)
	require.Len(t, added.Msg.RecoveryEmails, 1)
	assert.Equal(t, "spare@example.net", added.Msg.RecoveryEmails[0].Email)
	assert.NotZero(t, added.Msg.RecoveryEmails[0].VerifiedAt)

	// Listing needs a session, not a recent sign-in.
	listed, err := h.client.ListRecoveryEmails(ctx, authedReq(connect.NewRequest(&identitypb.ListRecoveryEmailsRequest{}), uid))
	require.NoError(t, err)
	require.Len(t, listed.Msg.RecoveryEmails, 1)
	assert.Zero(t, listed.Msg.HoldUntil)

	removed, err := h.client.RemoveRecoveryEmail(ctx,
		signedIn(connect.NewRequest(&identitypb.RemoveRecoveryEmailRequest{Email: "spare@example.net"}), uid))
	require.NoError(t, err)
	assert.Empty(t, removed.Msg.RecoveryEmails)

	_, err = h.client.RemoveRecoveryEmail(ctx,
		signedIn(connect.NewRequest(&identitypb.RemoveRecoveryEmailRequest{Email: "spare@example.net"}), uid))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestHandler_RecoveryEmails_Refusals(t *testing.T) {
	h, _ := newRecoveryEmailHarness(t, service.ProjectRecoveryEmailsConfig{Enabled: true})
	ctx := context.Background()
	uid := seedHandlerUser(t, h, "owner@example.com")

	// No session at all.
	_, err := h.client.RequestRecoveryEmail(ctx, connect.NewRequest(&identitypb.RequestRecoveryEmailRequest{Email: "spare@example.net"}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = h.client.VerifyRecoveryEmail(ctx, connect.NewRequest(&identitypb.VerifyRecoveryEmailRequest{Email: "spare@example.net", Code: "123456"}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = h.client.ListRecoveryEmails(ctx, connect.NewRequest(&identitypb.ListRecoveryEmailsRequest{}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = h.client.RemoveRecoveryEmail(ctx, connect.NewRequest(&identitypb.RemoveRecoveryEmailRequest{Email: "spare@example.net"}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = h.client.RemovePhone(ctx, connect.NewRequest(&identitypb.RemovePhoneRequest{}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

	// A session with no recent sign-in.
	_, err = h.client.RequestRecoveryEmail(ctx,
		authedReq(connect.NewRequest(&identitypb.RequestRecoveryEmailRequest{Email: "spare@example.net"}), uid))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	require.ErrorContains(t, err, "reauthentication_required")

	// A wrong code.
	_, err = h.client.RequestRecoveryEmail(ctx,
		signedIn(connect.NewRequest(&identitypb.RequestRecoveryEmailRequest{Email: "spare@example.net"}), uid))
	require.NoError(t, err)
	_, err = h.client.VerifyRecoveryEmail(ctx, signedIn(connect.NewRequest(&identitypb.VerifyRecoveryEmailRequest{
		Email: "spare@example.net", Code: "not-it",
	}), uid))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

	// A project that keeps none.
	off, _ := newRecoveryEmailHarness(t, service.ProjectRecoveryEmailsConfig{})
	offUID := seedHandlerUser(t, off, "owner@example.com")
	_, err = off.client.RequestRecoveryEmail(ctx,
		signedIn(connect.NewRequest(&identitypb.RequestRecoveryEmailRequest{Email: "spare@example.net"}), offUID))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

// A sign-in by a recovery email holds the session it opened from account
// security changes, adding a way in or taking one away alike, both the list
// and the refusal say until when, the held session can still end itself, and
// a session opened another way is not held.
func TestHandler_RecoverySignInHoldIsReported(t *testing.T) {
	h, mailer := newRecoveryEmailHarness(t, service.ProjectRecoveryEmailsConfig{Enabled: true, SignIn: true})
	ctx := context.Background()
	uid := seedHandlerUser(t, h, "owner@example.com")
	require.NoError(t, h.repo.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "spare@example.net", VerifiedAt: 1}, 5))
	require.NoError(t, h.repo.SetUserPhoneVerified(ctx, uid, "+14155550123", 1))

	_, err := h.client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: "spare@example.net"}))
	require.NoError(t, err)
	login, err := h.client.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{
		Email: "spare@example.net", Code: mailer.codeTo(t, "spare@example.net"),
	}))
	require.NoError(t, err)
	assert.Equal(t, uid, login.Msg.User.Id)
	assert.Equal(t, []string{service.AMRRecoveryEmail}, tokenAMR(t, login.Msg.AccessToken))

	listed, err := h.client.ListRecoveryEmails(ctx, authedReq(connect.NewRequest(&identitypb.ListRecoveryEmailsRequest{}), uid))
	require.NoError(t, err)
	holdUntil := listed.Msg.HoldUntil
	require.Greater(t, holdUntil, time.Now().Add(6*24*time.Hour).UnixMilli())

	requireHold := func(err error) {
		t.Helper()
		require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
		require.ErrorContains(t, err, "recovery_hold")
		var cerr *connect.Error
		require.True(t, errors.As(err, &cerr))
		require.Len(t, cerr.Details(), 1)
		msg, derr := cerr.Details()[0].Value()
		require.NoError(t, derr)
		details, ok := msg.(*identitypb.RecoveryHoldDetails)
		require.True(t, ok, "detail type = %T", msg)
		assert.Equal(t, holdUntil, details.HoldUntil)
	}
	_, err = h.client.RemoveRecoveryEmail(ctx,
		signedInByRecoveryEmail(connect.NewRequest(&identitypb.RemoveRecoveryEmailRequest{Email: "spare@example.net"}), uid))
	requireHold(err)
	_, err = h.client.RemovePhone(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.RemovePhoneRequest{}), uid))
	requireHold(err)
	_, err = h.client.BeginTotpSetup(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.BeginTotpSetupRequest{}), uid))
	requireHold(err)
	_, err = h.client.DisableTotp(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.DisableTotpRequest{Password: "pw"}), uid))
	requireHold(err)
	_, err = h.client.RegenerateRecoveryCodes(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.RegenerateRecoveryCodesRequest{Password: "pw"}), uid))
	requireHold(err)
	_, err = h.client.DeletePasskey(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.DeletePasskeyRequest{CredentialId: "cred-1"}), uid))
	requireHold(err)
	_, err = h.client.UnlinkIdentity(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.UnlinkIdentityRequest{Provider: "google", ProviderUserId: "g-1"}), uid))
	requireHold(err)
	_, err = h.client.ChangePassword(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.ChangePasswordRequest{CurrentPassword: "pw", NewPassword: "N3w!Str0ngPass"}), uid))
	requireHold(err)
	_, err = h.client.RequestEmailChange(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.RequestEmailChangeRequest{NewEmail: "moved@example.org", CurrentPassword: "pw"}), uid))
	requireHold(err)
	_, err = h.client.RevokeAllSessions(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.RevokeAllSessionsRequest{Password: "pw"}), uid))
	requireHold(err)
	_, err = h.client.SignOutEverywhere(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.SignOutEverywhereRequest{Password: "pw"}), uid))
	requireHold(err)
	_, err = h.client.DeleteMyAccount(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.DeleteMyAccountRequest{}), uid))
	requireHold(err)

	// The held session ends the owner's other session only by being it: the
	// token's sid names the session it is.
	expires := time.Now().Add(time.Hour).UnixMilli()
	for id, sid := range map[string]string{"owner-laptop": "sid-laptop", "recovery-phone": "sid-recovery"} {
		h.db.addRefreshToken(id, uid, expires)
		h.db.mu.Lock()
		h.db.nodes[id].Payload[tRfSID] = sid
		h.db.mu.Unlock()
	}
	revoke := func(sessionID string) error {
		req := signedInByRecoveryEmail(connect.NewRequest(&identitypb.RevokeSessionRequest{SessionId: sessionID}), uid)
		req.Header().Set(middleware.AuthenticatedSessionIDHeader, "sid-recovery")
		_, err := h.client.RevokeSession(ctx, req)
		return err
	}
	requireHold(revoke("owner-laptop"))
	require.NoError(t, revoke("recovery-phone"))

	// The owner's own session removes the address, and the hold is over.
	_, err = h.client.RemoveRecoveryEmail(ctx,
		signedIn(connect.NewRequest(&identitypb.RemoveRecoveryEmailRequest{Email: "spare@example.net"}), uid))
	require.NoError(t, err)
	listed, err = h.client.ListRecoveryEmails(ctx, authedReq(connect.NewRequest(&identitypb.ListRecoveryEmailsRequest{}), uid))
	require.NoError(t, err)
	assert.Zero(t, listed.Msg.HoldUntil)
}

func TestHandler_RemovePhone(t *testing.T) {
	h, _ := newRecoveryEmailHarness(t, service.ProjectRecoveryEmailsConfig{})
	ctx := context.Background()
	uid := seedHandlerUser(t, h, "owner@example.com")
	require.NoError(t, h.repo.SetUserPhoneVerified(ctx, uid, "+14155550123", 1))

	resp, err := h.client.RemovePhone(ctx, authedReq(connect.NewRequest(&identitypb.RemovePhoneRequest{}), uid))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.User.PhoneNumber)
	assert.False(t, resp.Msg.User.PhoneVerified)
}

// The new sentinels keep the codes clients are told to expect, wrapped or
// not, and the phone requirement is reported as its own selection refusal.
func TestToConnectError_RecoveryAndPhoneSentinels(t *testing.T) {
	for err, want := range map[error]connect.Code{
		service.ErrRecoveryEmailsDisabled:           connect.CodeFailedPrecondition,
		service.ErrRecoveryReauthenticationRequired: connect.CodeFailedPrecondition,
		service.ErrRecoveryEmailCodeInvalid:         connect.CodeUnauthenticated,
		service.ErrRecoveryEmailTaken:               connect.CodeAlreadyExists,
		service.ErrRecoveryEmailLimit:               connect.CodeResourceExhausted,
		service.ErrPhoneNumberTaken:                 connect.CodeAlreadyExists,
		service.ErrPhoneCountryNotAllowed:           connect.CodeFailedPrecondition,
		service.ErrPhoneVerificationRequired:        connect.CodeFailedPrecondition,
		service.ErrRecoverySession:                  connect.CodeFailedPrecondition,
	} {
		assert.Equal(t, want, connect.CodeOf(toConnectError(err)), "%v", err)
		assert.Equal(t, want, connect.CodeOf(toConnectError(fmt.Errorf("%w: detail", err))), "wrapped %v", err)
	}

	cerr := toConnectError(fmt.Errorf("refreshing: %w", &service.TenantSelectionRefusedError{
		Reason: service.TenantSelectionPhoneRequired, Err: service.ErrPhoneVerificationRequired,
	}))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(cerr))
	require.Len(t, cerr.Details(), 1)
	msg, err := cerr.Details()[0].Value()
	require.NoError(t, err)
	details, ok := msg.(*identitypb.TenantSelectionRefusedDetails)
	require.True(t, ok)
	assert.Equal(t, identitypb.TenantSelectionRefusal_TENANT_SELECTION_REFUSAL_PHONE_VERIFICATION_REQUIRED, details.GetReason())
}

func TestLoginPolicyPhoneRuleRoundTripsThroughTheProto(t *testing.T) {
	got := loginPolicyToProto(&service.LoginPolicy{RequireVerifiedPhone: true, PhoneCallingCodes: "91,44"})
	assert.True(t, got.RequireVerifiedPhone)
	assert.Equal(t, []string{"91", "44"}, got.PhoneCallingCodes)
	assert.Nil(t, loginPolicyToProto(&service.LoginPolicy{}).PhoneCallingCodes)
}

// On the wire, PasswordSignup answers an address an account keeps as a
// recovery email exactly as it answers a free one and a taken one: the same
// code, and the same fields filled.
func TestHandler_PasswordSignup_RecoveryEmailCannotBeToldApart(t *testing.T) {
	h, _ := newRecoveryEmailHarness(t, service.ProjectRecoveryEmailsConfig{Enabled: true})
	ctx := context.Background()
	uid := seedHandlerUser(t, h, "holder@example.com")
	require.NoError(t, h.repo.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "spare@example.com", VerifiedAt: 1}, 5))

	type shape struct {
		code                  connect.Code
		access, refresh, user bool
		expiresIn             int32
	}
	shapes := map[string]shape{}
	for _, addr := range []string{"free@example.com", "holder@example.com", "spare@example.com"} {
		resp, err := h.client.PasswordSignup(ctx, withClientHeaders(connect.NewRequest(&identitypb.PasswordSignupRequest{
			Email: addr, Password: strongPW,
		})))
		got := shape{code: connect.CodeOf(err)}
		if err == nil {
			m := resp.Msg
			got = shape{
				access: m.AccessToken != "", refresh: m.RefreshToken != "",
				user: m.User != nil && m.User.Email == addr, expiresIn: m.ExpiresIn,
			}
		}
		shapes[addr] = got
	}
	assert.Equal(t, shapes["free@example.com"], shapes["holder@example.com"])
	assert.Equal(t, shapes["free@example.com"], shapes["spare@example.com"])
	assert.True(t, shapes["spare@example.com"].access, "the answer is a success, as for a free address")
}
