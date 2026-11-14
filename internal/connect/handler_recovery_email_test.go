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

// recoveryClaims is what an access token says about the recovery email that
// opened its session.
type recoveryClaims struct {
	AMR             []string `json:"amr"`
	RecoveryEmailID string   `json:"recovery_email_id"`
}

// tokenRecoveryClaims reads the recoveryClaims of a token the harness minted.
// The signature is the server's business; this only looks at what the token
// says.
func tokenRecoveryClaims(t *testing.T, token string) recoveryClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims recoveryClaims
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// signedInByRecoveryEmail marks a request as coming from a session of
// userID's that a recovery email opened just now.
func signedInByRecoveryEmail[T any](r *connect.Request[T], userID, recoveryEmailID string) *connect.Request[T] {
	r.Header().Set(middleware.AuthenticatedAMRHeader, service.AMRRecoveryEmail)
	r.Header().Set(middleware.AuthenticatedRecoveryEmailIDHeader, recoveryEmailID)
	return signedIn(r, userID)
}

// recoveryHoldUntil is the hold_until of the RecoveryHoldDetails err carries,
// 0 when it carries none.
func recoveryHoldUntil(t *testing.T, err error) int64 {
	t.Helper()
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return 0
	}
	for _, detail := range cerr.Details() {
		msg, derr := detail.Value()
		require.NoError(t, derr)
		if hold, ok := msg.(*identitypb.RecoveryHoldDetails); ok {
			return hold.HoldUntil
		}
	}
	return 0
}

// seedProvenHandlerUser seeds an active account whose email is proven, which
// an account needs before it keeps a recovery email.
func seedProvenHandlerUser(t *testing.T, h *testHarness, email string) string {
	t.Helper()
	id, err := h.repo.CreateUser(context.Background(), &service.User{Email: email, EmailVerified: true, Status: "active", Role: "member"})
	require.NoError(t, err)
	return id
}

func TestHandler_RecoveryEmails_AddListRemove(t *testing.T) {
	h, mailer := newRecoveryEmailHarness(t, service.ProjectRecoveryEmailsConfig{Enabled: true})
	ctx := context.Background()
	uid := seedProvenHandlerUser(t, h, "owner@example.com")

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
	uid := seedProvenHandlerUser(t, h, "owner@example.com")

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
	require.ErrorContains(t, err, "recovery_emails_disabled", "the refusal carries a token apart from reauthentication_required")

	// An account whose own address is unproven.
	unproven := seedHandlerUser(t, h, "unproven@example.com")
	_, err = h.client.RequestRecoveryEmail(ctx,
		signedIn(connect.NewRequest(&identitypb.RequestRecoveryEmailRequest{Email: "planter@example.net"}), unproven))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	_, err = h.client.VerifyRecoveryEmail(ctx, signedIn(connect.NewRequest(&identitypb.VerifyRecoveryEmailRequest{
		Email: "planter@example.net", Code: "123456",
	}), unproven))
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
	recovery := tokenRecoveryClaims(t, login.Msg.AccessToken)
	assert.Equal(t, []string{service.AMRRecoveryEmail}, recovery.AMR)
	held, err := h.repo.ListRecoveryEmails(ctx, uid)
	require.NoError(t, err)
	require.Len(t, held, 1)
	assert.Equal(t, held[0].ID, recovery.RecoveryEmailID, "the token names the address by its id")
	assert.NotContains(t, login.Msg.AccessToken, "spare@example.net")

	listed, err := h.client.ListRecoveryEmails(ctx, authedReq(connect.NewRequest(&identitypb.ListRecoveryEmailsRequest{}), uid))
	require.NoError(t, err)
	holdUntil := listed.Msg.HoldUntil
	require.Greater(t, holdUntil, time.Now().Add(6*24*time.Hour).UnixMilli())
	require.Len(t, listed.Msg.RecoveryEmails, 1)
	assert.Equal(t, holdUntil-7*24*time.Hour.Milliseconds(), listed.Msg.RecoveryEmails[0].HoldStartedAt,
		"the list says which address started the hold, and when")
	assert.Equal(t, listed.Msg.RecoveryEmails[0].HoldStartedAt, listed.Msg.RecoveryEmails[0].LastSignInAt,
		"and when it last signed in, here the same sign-in")

	requireHold := func(err error, msgAndArgs ...any) {
		t.Helper()
		require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), msgAndArgs...)
		require.ErrorContains(t, err, "recovery_hold", msgAndArgs...)
		assert.Equal(t, holdUntil, recoveryHoldUntil(t, err), msgAndArgs...)
	}
	_, err = h.client.RemoveRecoveryEmail(ctx,
		signedInByRecoveryEmail(connect.NewRequest(&identitypb.RemoveRecoveryEmailRequest{Email: "spare@example.net"}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.RemovePhone(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.RemovePhoneRequest{}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.BeginTotpSetup(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.BeginTotpSetupRequest{}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.DisableTotp(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.DisableTotpRequest{Password: "pw"}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.RegenerateRecoveryCodes(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.RegenerateRecoveryCodesRequest{Password: "pw"}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.DeletePasskey(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.DeletePasskeyRequest{CredentialId: "cred-1"}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.UnlinkIdentity(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.UnlinkIdentityRequest{Provider: "google", ProviderUserId: "g-1"}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.ChangePassword(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.ChangePasswordRequest{CurrentPassword: "pw", NewPassword: "N3w!Str0ngPass"}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.RequestEmailChange(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.RequestEmailChangeRequest{NewEmail: "moved@example.org", CurrentPassword: "pw"}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.RevokeAllSessions(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.RevokeAllSessionsRequest{Password: "pw"}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.SignOutEverywhere(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.SignOutEverywhereRequest{Password: "pw"}), uid, recovery.RecoveryEmailID))
	requireHold(err)
	_, err = h.client.DeleteMyAccount(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.DeleteMyAccountRequest{}), uid, recovery.RecoveryEmailID))
	requireHold(err)

	// Nor does it hand out authority that would outlast the hold from any seat
	// the account holds: an OAuth-client admin's, a guardian's or a project
	// admin's.
	h.repo.mu.Lock()
	h.repo.users[uid].Role = service.RoleAdmin
	h.repo.mu.Unlock()
	h.db.addUser(uid, "owner@example.com", "Owner", service.RoleAdmin, "active")
	byRecovery := func(r interface{ Header() http.Header }) {
		r.Header().Set(middleware.AuthenticatedAMRHeader, service.AMRRecoveryEmail)
		r.Header().Set(middleware.AuthenticatedRecoveryEmailIDHeader, recovery.RecoveryEmailID)
		r.Header().Set(middleware.AuthenticatedAuthTimeHeader, strconv.FormatInt(time.Now().Unix(), 10))
		r.Header().Set("X-Authenticated-User-Id", uid)
	}
	child := "child-1"
	calls := map[string]func() error{
		"CreateOAuthClient": func() error {
			req := connect.NewRequest(&identitypb.CreateOAuthClientRequest{})
			byRecovery(req)
			_, err := h.client.CreateOAuthClient(ctx, req)
			return err
		},
		"UpdateOAuthClient": func() error {
			req := connect.NewRequest(&identitypb.UpdateOAuthClientRequest{ClientId: "client-1", ExpectedRevision: 1})
			byRecovery(req)
			_, err := h.client.UpdateOAuthClient(ctx, req)
			return err
		},
		"GrantParentalConsent": func() error {
			req := connect.NewRequest(&identitypb.GrantParentalConsentRequest{ChildUserId: child, PolicyVersion: "v1"})
			byRecovery(req)
			_, err := h.client.GrantParentalConsent(ctx, req)
			return err
		},
		"CreateManagedChildAccount": func() error {
			req := connect.NewRequest(&identitypb.CreateManagedChildAccountRequest{Username: "kid"})
			byRecovery(req)
			_, err := h.client.CreateManagedChildAccount(ctx, req)
			return err
		},
		"GetManagedChildProfile": func() error {
			req := connect.NewRequest(&identitypb.GetManagedChildProfileRequest{ChildUserId: child})
			byRecovery(req)
			_, err := h.client.GetManagedChildProfile(ctx, req)
			return err
		},
		"SetManagedChildPassword": func() error {
			req := connect.NewRequest(&identitypb.SetManagedChildPasswordRequest{ChildUserId: child, NewPassword: "N3w!Str0ngPass"})
			byRecovery(req)
			_, err := h.client.SetManagedChildPassword(ctx, req)
			return err
		},
		"SetManagedChildUsername": func() error {
			req := connect.NewRequest(&identitypb.SetManagedChildUsernameRequest{ChildUserId: child, Username: "kid"})
			byRecovery(req)
			_, err := h.client.SetManagedChildUsername(ctx, req)
			return err
		},
		"RevokeManagedChildSessions": func() error {
			req := connect.NewRequest(&identitypb.RevokeManagedChildSessionsRequest{ChildUserId: child})
			byRecovery(req)
			_, err := h.client.RevokeManagedChildSessions(ctx, req)
			return err
		},
		"DeactivateManagedChildAccount": func() error {
			req := connect.NewRequest(&identitypb.DeactivateManagedChildAccountRequest{ChildUserId: child})
			byRecovery(req)
			_, err := h.client.DeactivateManagedChildAccount(ctx, req)
			return err
		},
		"ReactivateManagedChildAccount": func() error {
			req := connect.NewRequest(&identitypb.ReactivateManagedChildAccountRequest{ChildUserId: child})
			byRecovery(req)
			_, err := h.client.ReactivateManagedChildAccount(ctx, req)
			return err
		},
		"DeleteManagedChildAccount": func() error {
			req := connect.NewRequest(&identitypb.DeleteManagedChildAccountRequest{ChildUserId: child})
			byRecovery(req)
			_, err := h.client.DeleteManagedChildAccount(ctx, req)
			return err
		},
		"InviteUser": func() error {
			req := connect.NewRequest(&identitypb.InviteUserRequest{Email: "new@example.com", Role: service.RoleAdmin, CreateImmediately: true})
			byRecovery(req)
			_, err := h.client.InviteUser(ctx, req)
			return err
		},
		"CreateUser": func() error {
			req := connect.NewRequest(&identitypb.CreateUserRequest{Email: "new@example.com", Role: service.RoleAdmin})
			byRecovery(req)
			_, err := h.client.CreateUser(ctx, req)
			return err
		},
		"UpdateUser": func() error {
			req := connect.NewRequest(&identitypb.UpdateUserRequest{UserId: uid, Role: service.RoleAdmin})
			byRecovery(req)
			_, err := h.client.UpdateUser(ctx, req)
			return err
		},
		"ResetUserPassword": func() error {
			req := connect.NewRequest(&identitypb.ResetUserPasswordRequest{UserId: "member-1"})
			byRecovery(req)
			_, err := h.client.ResetUserPassword(ctx, req)
			return err
		},
	}
	for name, call := range calls {
		requireHold(call(), name)
	}

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
		req := signedInByRecoveryEmail(connect.NewRequest(&identitypb.RevokeSessionRequest{SessionId: sessionID}), uid, recovery.RecoveryEmailID)
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
	got := loginPolicyToProto(&service.LoginPolicy{RequireVerifiedPhone: true, PhoneCallingCodes: []string{"91", "44"}})
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

// An admin whose recovery email signed in sets no account's password from the
// admin seat while the hold is in force, their own or another's. Once it has
// ended they reset other accounts' passwords as before, and still cannot give
// their own account a way in no recovery email marks: no password reset of
// their own comes back, as a temporary password or a reset token, and no
// other account is merged into theirs.
func TestHandler_AnAdminsRecoverySessionSetsNoPasswordDuringTheHoldAndNeverItsOwn(t *testing.T) {
	h, mailer := newRecoveryEmailHarness(t, service.ProjectRecoveryEmailsConfig{Enabled: true, SignIn: true})
	ctx := context.Background()
	uid := seedHandlerUser(t, h, "admin@example.com")
	h.db.addUser(uid, "admin@example.com", "Admin", "admin", "active")
	h.db.addUser("member-1", "member@example.com", "Member", "member", "active")
	require.NoError(t, h.repo.AddRecoveryEmail(ctx, &service.RecoveryEmail{UserID: uid, Email: "spare@example.net", VerifiedAt: 1}, 5))
	_, err := h.client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: "spare@example.net"}))
	require.NoError(t, err)
	login, err := h.client.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{
		Email: "spare@example.net", Code: mailer.codeTo(t, "spare@example.net"),
	}))
	require.NoError(t, err)
	recovery := tokenRecoveryClaims(t, login.Msg.AccessToken)
	listed, err := h.client.ListRecoveryEmails(ctx, authedReq(connect.NewRequest(&identitypb.ListRecoveryEmailsRequest{}), uid))
	require.NoError(t, err)
	require.NotZero(t, listed.Msg.HoldUntil, "the recovery sign-in holds the account")
	reset := func(userID string, temp bool) (*connect.Response[identitypb.ResetUserPasswordResponse], error) {
		return h.client.ResetUserPassword(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.ResetUserPasswordRequest{
			UserId: userID, GenerateTempPassword: temp,
		}), uid, recovery.RecoveryEmailID))
	}
	mergeIntoOwn := func() error {
		_, err := h.client.MergeUsers(ctx, signedInByRecoveryEmail(connect.NewRequest(&identitypb.MergeUsersRequest{
			SurvivorUserId: uid, OtherUserId: "member-1",
		}), uid, recovery.RecoveryEmailID))
		return err
	}

	for _, userID := range []string{uid, "member-1"} {
		for _, temp := range []bool{true, false} {
			got, err := reset(userID, temp)
			require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "reset of %s (temp=%t) during the hold: %v", userID, temp, err)
			require.Equal(t, listed.Msg.HoldUntil, recoveryHoldUntil(t, err), "the refusal says when the hold ends")
			require.Nil(t, got)
		}
	}
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(mergeIntoOwn()), "merging another account into their own during the hold")

	h.repo.mu.Lock()
	for _, e := range h.repo.recoveryEmails[uid] {
		e.HoldStartedAt = 1
	}
	h.repo.mu.Unlock()
	for _, temp := range []bool{true, false} {
		got, err := reset(uid, temp)
		require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "own password reset (temp=%t): %v", temp, err)
		require.Nil(t, got)
	}
	err = mergeIntoOwn()
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "merging another account into their own: %v", err)
	require.Zero(t, recoveryHoldUntil(t, err), "refused as a merge into the admin's own account, not by a hold")

	got, err := reset("member-1", false)
	require.NoError(t, err, "another account's reset is the admin's to do once the hold has ended")
	require.NotEmpty(t, got.Msg.ResetToken)
}

// A delegated-access call is held by what the caller's token says about its
// session, as every other held call is: the address that opened it and the
// session it is.
func TestAgentOAuthHuman_CarriesTheSessionsSignIn(t *testing.T) {
	req := signedInByRecoveryEmail(connect.NewRequest(&identitypb.DecideAgentAuthorizationRequest{}), "user-1", "recovery-1")
	req.Header().Set(middleware.AuthenticatedSessionIDHeader, "sid-1")
	human := agentOAuthHuman(req.Header())
	assert.Equal(t, "user-1", human.UserID)
	assert.Equal(t, []string{service.AMRRecoveryEmail}, human.SignIn.AMR)
	assert.Equal(t, "recovery-1", human.SignIn.RecoveryEmailID)
	assert.Equal(t, "sid-1", human.SignIn.SessionID)
	assert.NotZero(t, human.SignIn.AuthTimeSec)
}
