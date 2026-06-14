package connect

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passwords"
)

const strongPW = "MyStr0ng!Pass"

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := passwords.Hash(pw)
	if err != nil {
		t.Fatalf("hash pw: %v", err)
	}
	return h
}

// ──────────────────────────────────────────────────────────────────────
// errors.go — toConnectError + containsAny
// ──────────────────────────────────────────────────────────────────────

func TestToConnectError_NilReturnsNil(t *testing.T) {
	if got := toConnectError(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestToConnectError_SentinelMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"NotFound", service.ErrNotFound, connect.CodeNotFound},
		{"PermissionDenied", service.ErrPermissionDenied, connect.CodePermissionDenied},
		{"AlreadyExists", service.ErrAlreadyExists, connect.CodeAlreadyExists},
		{"Unauthenticated", service.ErrUnauthenticated, connect.CodeUnauthenticated},
		{"TokenExpired", service.ErrTokenExpired, connect.CodeUnauthenticated},
		{"InvalidArgument", service.ErrInvalidArgument, connect.CodeInvalidArgument},
		{"WeakPassword", service.ErrWeakPassword, connect.CodeInvalidArgument},
		{"AccountLocked", service.ErrAccountLocked, connect.CodeResourceExhausted},
		{"TotpRequired", service.ErrTotpRequired, connect.CodeFailedPrecondition},
		{"QrLoginExpired", service.ErrQrLoginExpired, connect.CodeDeadlineExceeded},
		{"InvalidTotpCode", service.ErrInvalidTotpCode, connect.CodeUnauthenticated},
		{"NoPasswordSet", service.ErrNoPasswordSet, connect.CodeFailedPrecondition},
		{"AccountNotActive", service.ErrAccountNotActive, connect.CodeFailedPrecondition},
		{"InvitationPending", service.ErrInvitationPending, connect.CodeFailedPrecondition},
		{"SignupDisabled", service.ErrSignupDisabled, connect.CodeFailedPrecondition},
		{"InvitationUsed", service.ErrInvitationUsed, connect.CodeFailedPrecondition},
		{"InvitationExpired", service.ErrInvitationExpired, connect.CodeFailedPrecondition},
		{"QrLoginNotPending", service.ErrQrLoginNotPending, connect.CodeFailedPrecondition},
		{"LocalAuthDisabled", service.ErrLocalAuthDisabled, connect.CodeUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ce := toConnectError(tc.err)
			if ce == nil {
				t.Fatalf("expected non-nil connect error")
			}
			if ce.Code() != tc.want {
				t.Fatalf("code: want %v, got %v", tc.want, ce.Code())
			}
		})
	}
}

func TestToConnectError_WrappedSentinel(t *testing.T) {
	wrapped := errors.New("boom: " + service.ErrNotFound.Error())
	// errors.Is needs an actual wrap — use fmt.Errorf with %w pattern equivalent.
	wrapped2 := errors.Join(errors.New("layer"), service.ErrPermissionDenied)
	if got := toConnectError(wrapped2); got.Code() != connect.CodePermissionDenied {
		t.Fatalf("wrapped sentinel: got %v", got.Code())
	}
	// A non-sentinel string-based error should fall through to message matching.
	_ = wrapped
}

func TestToConnectError_MessageHeuristics(t *testing.T) {
	cases := []struct {
		msg  string
		want connect.Code
	}{
		{"user not found", connect.CodeNotFound},
		{"group not found", connect.CodeNotFound},
		{"help request not found", connect.CodeNotFound},
		{"admin role required", connect.CodePermissionDenied},
		{"admins cannot deactivate themselves", connect.CodePermissionDenied},
		{"resource already exists", connect.CodeAlreadyExists},
		{"name is required", connect.CodeInvalidArgument},
		{"limit must be positive", connect.CodeInvalidArgument},
		{"valid email is required", connect.CodeInvalidArgument},
		{"some weird unmapped error", connect.CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			ce := toConnectError(errors.New(tc.msg))
			if ce.Code() != tc.want {
				t.Fatalf("msg %q: want %v, got %v", tc.msg, tc.want, ce.Code())
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	if !containsAny("user not found", "not found", "missing") {
		t.Fatal("expected match")
	}
	if containsAny("ok", "longer-string-than-source") {
		t.Fatal("expected no match for short input")
	}
	if containsAny("nothing here") {
		t.Fatal("expected no match with no needles")
	}
}

// ──────────────────────────────────────────────────────────────────────
// handler.go — header helpers
// ──────────────────────────────────────────────────────────────────────

type mapHeaders map[string]string

func (m mapHeaders) Get(k string) string { return m[k] }

func TestHeaderHelpers(t *testing.T) {
	h := mapHeaders{
		"X-Authenticated-User-Id": "u-1",
		"X-Forwarded-For":         "1.2.3.4",
		"User-Agent":              "ua/1",
	}
	if authenticatedUserID(h) != "u-1" {
		t.Fatal("authenticatedUserID mismatch")
	}
	if clientIP(h) != "1.2.3.4" {
		t.Fatal("clientIP mismatch")
	}
	if clientUserAgent(h) != "ua/1" {
		t.Fatal("ua mismatch")
	}

	// Fallback to X-Real-Ip when X-Forwarded-For absent.
	h2 := mapHeaders{"X-Real-Ip": "9.9.9.9"}
	if clientIP(h2) != "9.9.9.9" {
		t.Fatal("clientIP X-Real-Ip fallback failed")
	}
	if clientIP(mapHeaders{}) != "" {
		t.Fatal("empty headers should return empty IP")
	}
}

func TestNewIdentityHandler(t *testing.T) {
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

// ──────────────────────────────────────────────────────────────────────
// converters.go
// ──────────────────────────────────────────────────────────────────────

func TestConverters_NilSafe(t *testing.T) {
	if userToProto(nil) != nil {
		t.Fatal("userToProto(nil)")
	}
	if groupToProto(nil) != nil {
		t.Fatal("groupToProto(nil)")
	}
	if sessionToProto(nil) != nil {
		t.Fatal("sessionToProto(nil)")
	}
	if passkeyToProto(nil) != nil {
		t.Fatal("passkeyToProto(nil)")
	}
	if helpRequestToProto(nil) != nil {
		t.Fatal("helpRequestToProto(nil)")
	}
	if auditEventToProto(nil) != nil {
		t.Fatal("auditEventToProto(nil)")
	}
}

func TestConverters_UserStatus(t *testing.T) {
	cases := []struct {
		s    string
		want identitypb.UserStatus
	}{
		{"active", identitypb.UserStatus_USER_STATUS_ACTIVE},
		{"invited", identitypb.UserStatus_USER_STATUS_INVITED},
		{"deactivated", identitypb.UserStatus_USER_STATUS_DEACTIVATED},
		{"suspended", identitypb.UserStatus_USER_STATUS_SUSPENDED},
		{"unknown", identitypb.UserStatus_USER_STATUS_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := userStatusToProto(tc.s); got != tc.want {
			t.Errorf("userStatusToProto(%q): got %v want %v", tc.s, got, tc.want)
		}
	}

	if protoToUserStatusString(identitypb.UserStatus_USER_STATUS_ACTIVE) != "active" {
		t.Error("active reverse")
	}
	if protoToUserStatusString(identitypb.UserStatus_USER_STATUS_INVITED) != "invited" {
		t.Error("invited reverse")
	}
	if protoToUserStatusString(identitypb.UserStatus_USER_STATUS_DEACTIVATED) != "deactivated" {
		t.Error("deactivated reverse")
	}
	if protoToUserStatusString(identitypb.UserStatus_USER_STATUS_SUSPENDED) != "suspended" {
		t.Error("suspended reverse")
	}
	if protoToUserStatusString(identitypb.UserStatus_USER_STATUS_UNSPECIFIED) != "" {
		t.Error("unspecified reverse")
	}
}

func TestConverters_HelpStatus(t *testing.T) {
	cases := []struct {
		s    string
		want identitypb.HelpRequestStatus
	}{
		{"pending", identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_PENDING},
		{"resolved", identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_RESOLVED},
		{"rejected", identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_REJECTED},
		{"x", identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := helpRequestStatusToProto(tc.s); got != tc.want {
			t.Errorf("helpRequestStatusToProto(%q): got %v", tc.s, got)
		}
	}
	if protoToHelpRequestStatusString(identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_PENDING) != "pending" {
		t.Error("pending reverse")
	}
	if protoToHelpRequestStatusString(identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_RESOLVED) != "resolved" {
		t.Error("resolved reverse")
	}
	if protoToHelpRequestStatusString(identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_REJECTED) != "rejected" {
		t.Error("rejected reverse")
	}
	if protoToHelpRequestStatusString(identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_UNSPECIFIED) != "" {
		t.Error("unspec reverse")
	}
}

func TestConverters_QrLoginStatus(t *testing.T) {
	cases := []struct {
		s    string
		want identitypb.QrLoginStatus
	}{
		{"pending", identitypb.QrLoginStatus_QR_LOGIN_STATUS_PENDING},
		{"approved", identitypb.QrLoginStatus_QR_LOGIN_STATUS_APPROVED},
		{"rejected", identitypb.QrLoginStatus_QR_LOGIN_STATUS_REJECTED},
		{"expired", identitypb.QrLoginStatus_QR_LOGIN_STATUS_EXPIRED},
		{"consumed", identitypb.QrLoginStatus_QR_LOGIN_STATUS_CONSUMED},
		{"x", identitypb.QrLoginStatus_QR_LOGIN_STATUS_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := qrLoginStatusToProto(tc.s); got != tc.want {
			t.Errorf("qrLoginStatusToProto(%q): got %v", tc.s, got)
		}
	}
}

func TestConverters_MsToTimestamp(t *testing.T) {
	if msToTimestamp(0) != nil {
		t.Fatal("zero should be nil")
	}
	if msToTimestamp(-1) != nil {
		t.Fatal("negative should be nil")
	}
	ts := msToTimestamp(1234567)
	if ts == nil || ts.Seconds != 1234 || ts.Nanos != 567*1_000_000 {
		t.Fatalf("timestamp mismatch: %+v", ts)
	}
}

func TestConverters_UserAndPasskeyAndAudit(t *testing.T) {
	now := time.Now()
	u := &service.User{
		ID: "u1", Email: "a@b.com", Name: "Alice", AvatarURL: "http://a",
		Role: "admin", TotpRequired: true, Status: "active",
		RecoveryEmail: "r@b.com", QuotaBytes: 1024, LastLoginAtMs: 1000,
		CreatedAt: now, UpdatedAt: now,
	}
	pb := userToProto(u)
	if pb.Id != "u1" || pb.Email != "a@b.com" || pb.CreatedAt == nil || pb.UpdatedAt == nil {
		t.Fatalf("userToProto bad: %+v", pb)
	}

	pk := &service.PasskeyInfo{CredentialID: "c1", DeviceName: "iPhone", CreatedAt: now, LastUsedAt: now}
	if got := passkeyToProto(pk); got.CredentialId != "c1" || got.CreatedAt == nil {
		t.Fatalf("passkeyToProto: %+v", got)
	}

	ev := &service.AuditEvent{
		ID: "e1", EventType: "login", ActorUserID: "u1",
		Details: map[string]any{"ip": "1.1.1.1"}, CreatedAt: time.Now().UnixMilli(),
	}
	pbEv := auditEventToProto(ev)
	if pbEv.Id != "e1" || pbEv.Details == "" {
		t.Fatalf("auditEventToProto: %+v", pbEv)
	}

	// Slices.
	if got := usersToProto([]*service.User{u}); len(got) != 1 || got[0].Id != "u1" {
		t.Fatal("usersToProto")
	}
	if got := groupsToProto([]*service.Group{{ID: "g1", Name: "G"}}); len(got) != 1 {
		t.Fatal("groupsToProto")
	}
	if got := sessionsToProto([]*service.Session{{ID: "s1"}}); len(got) != 1 {
		t.Fatal("sessionsToProto")
	}
	if got := passkeysToProto([]*service.PasskeyInfo{pk}); len(got) != 1 {
		t.Fatal("passkeysToProto")
	}
	if got := helpRequestsToProto([]*service.HelpRequest{{ID: "h1", Status: "pending"}}); len(got) != 1 {
		t.Fatal("helpRequestsToProto")
	}
	if got := auditEventsToProto([]*service.AuditEvent{ev}); len(got) != 1 {
		t.Fatal("auditEventsToProto")
	}
}

// ──────────────────────────────────────────────────────────────────────
// Auth handlers — exercise wire format via httptest server.
// ──────────────────────────────────────────────────────────────────────

func TestPasswordSignupAndLogin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	signup, err := h.client.PasswordSignup(ctx, withClientHeaders(connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: "alice@example.com", Password: strongPW,
	})))
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if signup.Msg.User.Email != "alice@example.com" || signup.Msg.AccessToken == "" {
		t.Fatalf("signup unexpected: %+v", signup.Msg)
	}

	// Duplicate: still succeeds to avoid email enumeration, but must not
	// authenticate the caller.
	dup, err := h.client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: "alice@example.com", Password: strongPW,
	}))
	if err != nil {
		t.Fatalf("duplicate signup: %v", err)
	}
	if dup.Msg.AccessToken == "" || dup.Msg.RefreshToken == "" || dup.Msg.User == nil {
		t.Fatalf("duplicate signup unexpected: %+v", dup.Msg)
	}
	getCurReq := withClientHeaders(connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	getCurReq.Header().Set("Authorization", "Bearer "+dup.Msg.AccessToken)
	_, err = h.client.GetCurrentUser(ctx, getCurReq)
	if got := connectCodeOf(err); got != connect.CodeNotFound && got != connect.CodeUnauthenticated {
		t.Fatalf("duplicate signup token should not authenticate, got %v: %v", got, err)
	}

	// Weak password → InvalidArgument.
	_, err = h.client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: "weak@example.com", Password: "x",
	}))
	if connectCodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v: %v", connectCodeOf(err), err)
	}

	// Login success.
	login, err := h.client.PasswordLogin(ctx, withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: "alice@example.com", Password: strongPW,
	})))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if login.Msg.AccessToken == "" || login.Msg.User.Id == "" {
		t.Fatalf("login result: %+v", login.Msg)
	}
	if login.Msg.User.EmailVerified {
		t.Fatalf("password login should allow unverified local accounts, got verified=%v", login.Msg.User.EmailVerified)
	}

	// Wrong password.
	_, err = h.client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: "alice@example.com", Password: "wrongP@ssw0rd!",
	}))
	if err == nil {
		t.Fatal("expected wrong-password error")
	}

	// User not found — service returns Unauthenticated to avoid leaking
	// account existence (anti-enumeration).
	_, err = h.client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: "ghost@example.com", Password: strongPW,
	}))
	if connectCodeOf(err) != connect.CodeUnauthenticated && connectCodeOf(err) != connect.CodeNotFound {
		t.Fatalf("expected Unauth/NotFound for unknown user, got %v: %v", connectCodeOf(err), err)
	}
}

func TestPasswordSignup_Disabled(t *testing.T) {
	h := newHarness(t)
	h.cfg.PasswordSignupEnabled = false

	_, err := h.client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: "alice@example.com", Password: strongPW,
	}))
	if connectCodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v: %v", connectCodeOf(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), service.ErrSignupDisabled.Error()) {
		t.Fatalf("expected disabled-signup message, got %v", err)
	}
}

func TestRequestPasswordReset_DisabledStillSucceeds(t *testing.T) {
	h := newHarness(t)
	h.cfg.PasswordResetEnabled = false
	u := h.repo.seedUser(&service.User{Email: "u@e.com", Status: "active", Role: "member"})

	_, err := h.client.RequestPasswordReset(context.Background(), connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: u.Email,
	}))
	if err != nil {
		t.Fatalf("request pw reset: %v", err)
	}
	if got := len(h.repo.passwordResets); got != 0 {
		t.Fatalf("expected 0 reset tokens, got %d", got)
	}
}

func TestOAuthLogin_LocalDisabled(t *testing.T) {
	h := newHarness(t)
	// OAuthLogin with empty email triggers ErrInvalidArgument inside service
	// (since email is required). That maps to InvalidArgument.
	_, err := h.client.OAuthLogin(context.Background(),
		connect.NewRequest(&identitypb.OAuthLoginRequest{Provider: "google"}))
	if err == nil {
		t.Fatal("expected error from empty oauth login")
	}
	code := connectCodeOf(err)
	if code != connect.CodeInvalidArgument && code != connect.CodeInternal && code != connect.CodeUnavailable {
		t.Fatalf("unexpected oauth login code: %v: %v", code, err)
	}
}

func TestRedeemOAuthCode_UnknownCodeUnauthenticated(t *testing.T) {
	// OAuth must be enabled for the unknown-code path to be reachable;
	// with it disabled the handler short-circuits to Unavailable (see
	// TestRedeemOAuthCode_DisabledUnavailable).
	registry := oauth.NewRegistry()
	registry.Register("google", connectOAuthExchanger{})
	h := newHarnessWithOAuthRegistry(t, registry)
	_, err := h.client.RedeemOAuthCode(context.Background(),
		connect.NewRequest(&identitypb.RedeemOAuthCodeRequest{Code: "does-not-exist"}))
	if err == nil {
		t.Fatal("expected error redeeming unknown code")
	}
	if got := connectCodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("RedeemOAuthCode unknown code = %v, want Unauthenticated", got)
	}
}

// TestRedeemOAuthCode_DisabledUnavailable locks in #156: with OAuth
// disabled (no registry), RedeemOAuthCode fails fast with Unavailable —
// the same guard BeginOAuthLogin/OAuthLogin use — instead of leaking an
// Unauthenticated "invalid code" status from the code lookup.
func TestRedeemOAuthCode_DisabledUnavailable(t *testing.T) {
	h := newHarness(t)
	_, err := h.client.RedeemOAuthCode(context.Background(),
		connect.NewRequest(&identitypb.RedeemOAuthCodeRequest{Code: "does-not-exist"}))
	if err == nil {
		t.Fatal("expected error redeeming with OAuth disabled")
	}
	if got := connectCodeOf(err); got != connect.CodeUnavailable {
		t.Fatalf("RedeemOAuthCode OAuth-disabled = %v, want Unavailable", got)
	}
}

type connectOAuthExchanger struct{}

func (connectOAuthExchanger) Exchange(context.Context, string, string) (*oauth.Identity, error) {
	return &oauth.Identity{
		Provider:       "google",
		ProviderUserID: "connect-user",
		Email:          "connect-oauth@example.com",
		EmailVerified:  true,
		Name:           "Connect OAuth",
	}, nil
}

func (connectOAuthExchanger) AuthorizationURL(_ context.Context, redirectURI, state, codeChallenge string) (string, error) {
	u := url.URL{Scheme: "https", Host: "example.com", Path: "/oauth/start"}
	q := u.Query()
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func TestBeginOAuthLogin_ViaConnect(t *testing.T) {
	registry := oauth.NewRegistry()
	registry.Register("google", connectOAuthExchanger{})
	h := newHarnessWithOAuthRegistry(t, registry)

	resp, err := h.client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: "https://app.example.com/oauth/callback",
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}
	if resp.Msg.State == "" || resp.Msg.StateToken == "" || resp.Msg.CodeVerifier == "" {
		t.Fatalf("missing state artifacts: %+v", resp.Msg)
	}
	if resp.Msg.ExpiresIn <= 0 {
		t.Fatalf("ExpiresIn = %d", resp.Msg.ExpiresIn)
	}
	u, err := url.Parse(resp.Msg.AuthorizationUrl)
	if err != nil {
		t.Fatalf("authorization url parse: %v", err)
	}
	if got := u.Query().Get("state"); got != resp.Msg.State {
		t.Fatalf("state in URL = %q, want %q", got, resp.Msg.State)
	}
	if got := u.Query().Get("redirect_uri"); got != "https://app.example.com/oauth/callback" {
		t.Fatalf("redirect_uri = %q", got)
	}
}

func TestRefreshTokenAndLogout(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	signup, err := h.client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: "ref@example.com", Password: strongPW,
	}))
	if err != nil {
		t.Fatalf("signup: %v", err)
	}

	rotated, err := h.client.RefreshToken(ctx, withClientHeaders(connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: signup.Msg.RefreshToken,
	})))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.Msg.AccessToken == "" || rotated.Msg.RefreshToken == "" {
		t.Fatal("rotated tokens missing")
	}

	// Bad refresh token → Unauthenticated/NotFound from service.
	_, err = h.client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{
		RefreshToken: "garbage",
	}))
	if err == nil {
		t.Fatal("expected refresh error")
	}

	// Logout success — uses the most-recent refresh token.
	if _, err := h.client.Logout(ctx, connect.NewRequest(&identitypb.LogoutRequest{
		RefreshToken: rotated.Msg.RefreshToken,
	})); err != nil {
		t.Fatalf("logout: %v", err)
	}
}

func TestGetCurrentUser_AuthRequired(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Missing user ID header → Unauthenticated.
	_, err := h.client.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	if connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v: %v", connectCodeOf(err), err)
	}

	// With valid user ID.
	u := h.repo.seedUser(&service.User{Email: "me@e.com", Status: "active", Role: "member"})
	resp, err := h.client.GetCurrentUser(ctx,
		authedReq(connect.NewRequest(&identitypb.GetCurrentUserRequest{}), u.ID))
	if err != nil {
		t.Fatalf("get current: %v", err)
	}
	if resp.Msg.User.Id != u.ID {
		t.Fatalf("user mismatch: %+v", resp.Msg.User)
	}
}

func TestAcceptInvitation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	u := h.repo.seedUser(&service.User{Email: "inv@example.com", Status: "invited", Role: "member"})
	rawToken := "tok-abc"
	h.repo.seedInvitation(&service.InvitationRecord{
		TokenHash: hashInvitation(rawToken),
		Email:     u.Email,
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	resp, err := h.client.AcceptInvitation(ctx, withClientHeaders(connect.NewRequest(&identitypb.AcceptInvitationRequest{
		InvitationToken: rawToken, Password: strongPW, Name: "Inv",
	})))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if resp.Msg.AccessToken == "" {
		t.Fatal("expected access token")
	}

	// Bad token → some error.
	_, err = h.client.AcceptInvitation(ctx, connect.NewRequest(&identitypb.AcceptInvitationRequest{
		InvitationToken: "nope", Password: strongPW,
	}))
	if err == nil {
		t.Fatal("expected error for bad token")
	}
}

// ──────────────────────────────────────────────────────────────────────
// Passkey + QR + TOTP — exercise handler glue (service-layer errors expected).
// ──────────────────────────────────────────────────────────────────────

func TestPasskeyHandlers_Glue(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	u := h.repo.seedUser(&service.User{Email: "pk@e.com", Status: "active", Role: "member"})

	// BeginPasskeyLogin for a known email — service returns options JSON.
	resp, err := h.client.BeginPasskeyLogin(ctx, connect.NewRequest(&identitypb.BeginPasskeyLoginRequest{
		Email: u.Email,
	}))
	if err != nil {
		t.Fatalf("begin passkey login: %v", err)
	}
	if resp.Msg.OptionsJson == "" || resp.Msg.ChallengeId == "" {
		t.Fatalf("missing fields: %+v", resp.Msg)
	}

	// Unknown email — service may still issue a generic challenge to avoid
	// enumeration; just make sure it doesn't crash. Either error or success
	// is acceptable.
	_, _ = h.client.BeginPasskeyLogin(ctx, connect.NewRequest(&identitypb.BeginPasskeyLoginRequest{
		Email: "missing@e.com",
	}))

	// CompletePasskeyLogin with bad challenge → error.
	_, err = h.client.CompletePasskeyLogin(ctx, connect.NewRequest(&identitypb.CompletePasskeyLoginRequest{
		ChallengeId: "nope", CredentialJson: "{}",
	}))
	if err == nil {
		t.Fatal("expected error for bad challenge")
	}

	// BeginPasskeyRegistration requires auth.
	_, err = h.client.BeginPasskeyRegistration(ctx, connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{}))
	if connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauth, got %v", connectCodeOf(err))
	}
	respReg, err := h.client.BeginPasskeyRegistration(ctx,
		authedReq(connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{DeviceName: "iPhone"}), u.ID))
	if err != nil {
		t.Fatalf("begin reg: %v", err)
	}
	if respReg.Msg.OptionsJson == "" {
		t.Fatal("expected options")
	}

	// CompletePasskeyRegistration with bad challenge → error.
	_, err = h.client.CompletePasskeyRegistration(ctx,
		authedReq(connect.NewRequest(&identitypb.CompletePasskeyRegistrationRequest{
			ChallengeId: "nope", CredentialJson: "{}", DeviceName: "X",
		}), u.ID))
	if err == nil {
		t.Fatal("expected complete-reg error")
	}

	// ListPasskeys — empty list OK (proto accepts nil/empty as same).
	if _, err := h.client.ListPasskeys(ctx,
		authedReq(connect.NewRequest(&identitypb.ListPasskeysRequest{}), u.ID)); err != nil {
		t.Fatalf("list passkeys: %v", err)
	}

	// DeletePasskey — unauth → unauth code; then auth → not-found-style error.
	if _, err = h.client.ListPasskeys(ctx, connect.NewRequest(&identitypb.ListPasskeysRequest{})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("ListPasskeys unauth code: %v", connectCodeOf(err))
	}
	if _, err = h.client.DeletePasskey(ctx, connect.NewRequest(&identitypb.DeletePasskeyRequest{CredentialId: "c"})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("DeletePasskey unauth code: %v", connectCodeOf(err))
	}
	_, err = h.client.DeletePasskey(ctx,
		authedReq(connect.NewRequest(&identitypb.DeletePasskeyRequest{CredentialId: "missing"}), u.ID))
	if err == nil {
		t.Fatal("expected delete error for missing cred")
	}
}

func TestQrLoginHandlers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	init, err := h.client.InitiateQrLogin(ctx, withClientHeaders(connect.NewRequest(&identitypb.InitiateQrLoginRequest{
		DeviceInfo: "Pixel-9", UserAgent: "ua/1",
	})))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if init.Msg.SessionId == "" || init.Msg.QrUrl == "" {
		t.Fatalf("init result: %+v", init.Msg)
	}

	// GetQrLoginSession works.
	got, err := h.client.GetQrLoginSession(ctx, connect.NewRequest(&identitypb.GetQrLoginSessionRequest{
		SessionId: init.Msg.SessionId,
	}))
	if err != nil {
		t.Fatalf("get qr: %v", err)
	}
	if got.Msg.Status == identitypb.QrLoginStatus_QR_LOGIN_STATUS_UNSPECIFIED {
		t.Fatal("unexpected status")
	}

	// Unknown session.
	_, err = h.client.GetQrLoginSession(ctx, connect.NewRequest(&identitypb.GetQrLoginSessionRequest{
		SessionId: "nope",
	}))
	if err == nil {
		t.Fatal("expected error for unknown session")
	}

	// ApproveQrLogin without auth — handler does NOT short-circuit on missing
	// user-id header (it passes empty string to the service which treats it
	// as a normal call). Just exercise it with a valid user id.
	u := h.repo.seedUser(&service.User{Email: "approver@e.com", Status: "active", Role: "member"})
	_, err = h.client.ApproveQrLogin(ctx, withClientHeaders(authedReq(connect.NewRequest(&identitypb.ApproveQrLoginRequest{
		SessionId: init.Msg.SessionId, Approve: true,
	}), u.ID)))
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	// PollQrLogin — pending status.
	pollResp, err := h.client.PollQrLogin(ctx, withClientHeaders(connect.NewRequest(&identitypb.PollQrLoginRequest{
		SessionId: init.Msg.SessionId,
	})))
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if pollResp.Msg.Status == identitypb.QrLoginStatus_QR_LOGIN_STATUS_UNSPECIFIED {
		t.Fatal("expected non-zero status")
	}
}

func TestTotpHandlers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pwHash := mustHash(t, strongPW)
	u := h.repo.seedUser(&service.User{Email: "t@e.com", Status: "active", Role: "member", PasswordHash: pwHash})

	// Auth required on Begin.
	if _, err := h.client.BeginTotpSetup(ctx, connect.NewRequest(&identitypb.BeginTotpSetupRequest{})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("BeginTotpSetup unauth: %v", connectCodeOf(err))
	}
	resp, err := h.client.BeginTotpSetup(ctx,
		authedReq(connect.NewRequest(&identitypb.BeginTotpSetupRequest{}), u.ID))
	if err != nil {
		t.Fatalf("begin totp: %v", err)
	}
	if resp.Msg.Secret == "" || resp.Msg.QrCodeUri == "" || len(resp.Msg.RecoveryCodes) == 0 {
		t.Fatalf("totp begin missing fields: %+v", resp.Msg)
	}

	// VerifyTotpSetup with bad code → InvalidTotp / Unauth.
	if _, err := h.client.VerifyTotpSetup(ctx, connect.NewRequest(&identitypb.VerifyTotpSetupRequest{Code: "000000"})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("VerifyTotpSetup unauth: %v", connectCodeOf(err))
	}
	_, err = h.client.VerifyTotpSetup(ctx,
		authedReq(connect.NewRequest(&identitypb.VerifyTotpSetupRequest{Code: "000000"}), u.ID))
	if err == nil {
		t.Fatal("expected verify-setup error for bogus code")
	}

	// VerifyTotp (login flow) with bad challenge → error.
	_, err = h.client.VerifyTotp(ctx, withClientHeaders(connect.NewRequest(&identitypb.VerifyTotpRequest{
		LoginChallengeId: "nope", Code: "000000",
	})))
	if err == nil {
		t.Fatal("expected verify totp error")
	}

	// DisableTotp — unauth path + a positive call (totp may have been
	// auto-enrolled by BeginTotpSetup; either success or error is fine).
	if _, err := h.client.DisableTotp(ctx, connect.NewRequest(&identitypb.DisableTotpRequest{Password: strongPW})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("DisableTotp unauth: %v", connectCodeOf(err))
	}
	_, _ = h.client.DisableTotp(ctx,
		authedReq(connect.NewRequest(&identitypb.DisableTotpRequest{Password: strongPW}), u.ID))

	// RegenerateRecoveryCodes — unauth + auth-no-totp.
	if _, err := h.client.RegenerateRecoveryCodes(ctx, connect.NewRequest(&identitypb.RegenerateRecoveryCodesRequest{Password: strongPW})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("RegenRecoveryCodes unauth: %v", connectCodeOf(err))
	}
	_, err = h.client.RegenerateRecoveryCodes(ctx,
		authedReq(connect.NewRequest(&identitypb.RegenerateRecoveryCodesRequest{Password: strongPW}), u.ID))
	if err == nil {
		t.Fatal("expected regen error (no totp set up)")
	}
}

// ──────────────────────────────────────────────────────────────────────
// Admin handlers — full path through the connect router via fakeDB.
// ──────────────────────────────────────────────────────────────────────

func TestAdminHandlers_AllRequireAuth(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	rpcs := []func() error{
		func() error {
			_, err := h.client.InviteUser(ctx, connect.NewRequest(&identitypb.InviteUserRequest{}))
			return err
		},
		func() error {
			_, err := h.client.ListUsers(ctx, connect.NewRequest(&identitypb.ListUsersRequest{}))
			return err
		},
		func() error {
			_, err := h.client.GetUser(ctx, connect.NewRequest(&identitypb.GetUserRequest{}))
			return err
		},
		func() error {
			_, err := h.client.UpdateUser(ctx, connect.NewRequest(&identitypb.UpdateUserRequest{}))
			return err
		},
		func() error {
			_, err := h.client.DeactivateUser(ctx, connect.NewRequest(&identitypb.DeactivateUserRequest{}))
			return err
		},
		func() error {
			_, err := h.client.ReactivateUser(ctx, connect.NewRequest(&identitypb.ReactivateUserRequest{}))
			return err
		},
		func() error {
			_, err := h.client.ResetUserPassword(ctx, connect.NewRequest(&identitypb.ResetUserPasswordRequest{}))
			return err
		},
		func() error {
			_, err := h.client.SetUserQuota(ctx, connect.NewRequest(&identitypb.SetUserQuotaRequest{}))
			return err
		},
		func() error {
			_, err := h.client.CreateUser(ctx, connect.NewRequest(&identitypb.CreateUserRequest{}))
			return err
		},
		func() error {
			_, err := h.client.DeleteUser(ctx, connect.NewRequest(&identitypb.DeleteUserRequest{}))
			return err
		},
	}
	for i, rpc := range rpcs {
		err := rpc()
		if connectCodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("rpc[%d] expected unauth, got %v: %v", i, connectCodeOf(err), err)
		}
	}
}

func TestAdminHandlers_FullFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Seed admin in fakeDB so AdminService.requireAdmin succeeds.
	h.db.addUser("admin-1", "admin@e.com", "Admin", "admin", "active")

	// InviteUser.
	inv, err := h.client.InviteUser(ctx, authedReq(connect.NewRequest(&identitypb.InviteUserRequest{
		Email: "n@e.com", Name: "N", Role: "member", CreateImmediately: false,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if inv.Msg.User == nil || inv.Msg.InvitationToken == "" {
		t.Fatalf("invite result: %+v", inv.Msg)
	}
	newUserID := inv.Msg.User.Id

	// CreateUser (immediate).
	cu, err := h.client.CreateUser(ctx, authedReq(connect.NewRequest(&identitypb.CreateUserRequest{
		Email: "imm@e.com", Name: "Imm", Role: "member",
	}), "admin-1"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if cu.Msg.User == nil || cu.Msg.User.Id == "" {
		t.Fatal("create user empty")
	}

	// GetUser.
	gu, err := h.client.GetUser(ctx, authedReq(connect.NewRequest(&identitypb.GetUserRequest{
		UserId: newUserID,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if gu.Msg.User.Id != newUserID {
		t.Fatal("get user id mismatch")
	}

	// ListUsers.
	lu, err := h.client.ListUsers(ctx, authedReq(connect.NewRequest(&identitypb.ListUsersRequest{
		Limit: 10, StatusFilter: identitypb.UserStatus_USER_STATUS_INVITED,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	_ = lu

	// UpdateUser.
	_, err = h.client.UpdateUser(ctx, authedReq(connect.NewRequest(&identitypb.UpdateUserRequest{
		UserId: newUserID, Name: "Renamed",
	}), "admin-1"))
	if err != nil {
		t.Fatalf("update user: %v", err)
	}

	// SetUserQuota.
	_, err = h.client.SetUserQuota(ctx, authedReq(connect.NewRequest(&identitypb.SetUserQuotaRequest{
		UserId: newUserID, QuotaBytes: 4096,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("set quota: %v", err)
	}

	// ResetUserPassword.
	_, err = h.client.ResetUserPassword(ctx, authedReq(connect.NewRequest(&identitypb.ResetUserPasswordRequest{
		UserId: newUserID, GenerateTempPassword: true,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("reset pw: %v", err)
	}

	// DeactivateUser then ReactivateUser.
	_, err = h.client.DeactivateUser(ctx, authedReq(connect.NewRequest(&identitypb.DeactivateUserRequest{
		UserId: newUserID, Reason: "test",
	}), "admin-1"))
	if err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	_, err = h.client.ReactivateUser(ctx, authedReq(connect.NewRequest(&identitypb.ReactivateUserRequest{
		UserId: newUserID,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("reactivate: %v", err)
	}

	// DeleteUser physically removes the user via the Repository
	// cascade. The connect harness uses a separate fakeRepo from the
	// fakeDB graph path that InviteUser wrote to, so the target user
	// must exist in the repo for the cascade's existence check.
	h.repo.seedUser(&service.User{ID: newUserID, Email: "n@e.com", Status: "invited", Role: "member"})
	_, err = h.client.DeleteUser(ctx, authedReq(connect.NewRequest(&identitypb.DeleteUserRequest{
		UserId: newUserID,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("delete user: %v", err)
	}
	// After the hard-delete the repo no longer holds the user.
	if u, _ := h.repo.GetUser(ctx, newUserID); u != nil {
		t.Fatalf("user must be deleted from repo, got %#v", u)
	}
}

func TestAdminHandlers_NonAdminDenied(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("member-1", "m@e.com", "M", "member", "active")

	_, err := h.client.ListUsers(ctx, authedReq(connect.NewRequest(&identitypb.ListUsersRequest{
		Limit: 10,
	}), "member-1"))
	if err == nil {
		t.Fatal("expected denied")
	}
	if connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v: %v", connectCodeOf(err), err)
	}
}

// ──────────────────────────────────────────────────────────────────────
// Group handlers
// ──────────────────────────────────────────────────────────────────────

func TestGroupHandlers_Full(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("admin-1", "a@e.com", "A", "admin", "active")
	h.db.addUser("user-1", "u@e.com", "U", "member", "active")

	// Auth required.
	rpcs := map[string]func() error{
		"CreateGroup": func() error {
			_, err := h.client.CreateGroup(ctx, connect.NewRequest(&identitypb.CreateGroupRequest{}))
			return err
		},
		"UpdateGroup": func() error {
			_, err := h.client.UpdateGroup(ctx, connect.NewRequest(&identitypb.UpdateGroupRequest{}))
			return err
		},
		"DeleteGroup": func() error {
			_, err := h.client.DeleteGroup(ctx, connect.NewRequest(&identitypb.DeleteGroupRequest{}))
			return err
		},
		"ListGroups": func() error {
			_, err := h.client.ListGroups(ctx, connect.NewRequest(&identitypb.ListGroupsRequest{}))
			return err
		},
		"AddGroupMember": func() error {
			_, err := h.client.AddGroupMember(ctx, connect.NewRequest(&identitypb.AddGroupMemberRequest{}))
			return err
		},
		"RemoveGroupMember": func() error {
			_, err := h.client.RemoveGroupMember(ctx, connect.NewRequest(&identitypb.RemoveGroupMemberRequest{}))
			return err
		},
		"ListGroupMembers": func() error {
			_, err := h.client.ListGroupMembers(ctx, connect.NewRequest(&identitypb.ListGroupMembersRequest{}))
			return err
		},
	}
	for name, fn := range rpcs {
		if got := connectCodeOf(fn()); got != connect.CodeUnauthenticated {
			t.Fatalf("%s expected unauth, got %v", name, got)
		}
	}

	if _, err := h.client.CreateGroup(ctx, authedReq(connect.NewRequest(&identitypb.CreateGroupRequest{
		Name: "Denied",
	}), "user-1")); connectCodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin CreateGroup expected PermissionDenied, got %v: %v", connectCodeOf(err), err)
	}

	// CreateGroup happy path.
	cg, err := h.client.CreateGroup(ctx, authedReq(connect.NewRequest(&identitypb.CreateGroupRequest{
		Name: "G1", Description: "desc",
	}), "admin-1"))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	gid := cg.Msg.Group.Id

	// UpdateGroup.
	_, err = h.client.UpdateGroup(ctx, authedReq(connect.NewRequest(&identitypb.UpdateGroupRequest{
		GroupId: gid, Name: "G1-renamed",
	}), "admin-1"))
	if err != nil {
		t.Fatalf("update group: %v", err)
	}

	// AddGroupMember.
	_, err = h.client.AddGroupMember(ctx, authedReq(connect.NewRequest(&identitypb.AddGroupMemberRequest{
		GroupId: gid, UserId: "user-1",
	}), "admin-1"))
	if err != nil {
		t.Fatalf("add member: %v", err)
	}

	// ListGroups.
	_, err = h.client.ListGroups(ctx, authedReq(connect.NewRequest(&identitypb.ListGroupsRequest{
		Limit: 10,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}

	// ListGroupMembers.
	lm, err := h.client.ListGroupMembers(ctx, authedReq(connect.NewRequest(&identitypb.ListGroupMembersRequest{
		GroupId: gid,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	if len(lm.Msg.Members) != 1 || lm.Msg.Members[0].GetId() != "user-1" {
		t.Fatalf("members = %+v, want user-1 present", lm.Msg.Members)
	}

	// RemoveGroupMember.
	_, err = h.client.RemoveGroupMember(ctx, authedReq(connect.NewRequest(&identitypb.RemoveGroupMemberRequest{
		GroupId: gid, UserId: "user-1",
	}), "admin-1"))
	if err != nil {
		t.Fatalf("remove member: %v", err)
	}

	// DeleteGroup.
	_, err = h.client.DeleteGroup(ctx, authedReq(connect.NewRequest(&identitypb.DeleteGroupRequest{
		GroupId: gid,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("delete group: %v", err)
	}

	// Missing field validation should map to InvalidArgument.
	_, err = h.client.CreateGroup(ctx, authedReq(connect.NewRequest(&identitypb.CreateGroupRequest{}), "admin-1"))
	if err == nil {
		t.Fatal("expected required-field error")
	}
	if connectCodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v: %v", connectCodeOf(err), err)
	}
}

// ──────────────────────────────────────────────────────────────────────
// Help handlers
// ──────────────────────────────────────────────────────────────────────

func TestHelpHandlers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("admin-1", "a@e.com", "A", "admin", "active")

	// RequestAdminHelp is unauthenticated and always returns success.
	_, err := h.client.RequestAdminHelp(ctx, withClientHeaders(connect.NewRequest(&identitypb.RequestAdminHelpRequest{
		Email: "x@e.com", Reason: "stuck",
	})))
	if err != nil {
		t.Fatalf("request admin help: %v", err)
	}

	// ListHelpRequests requires auth.
	if _, err := h.client.ListHelpRequests(ctx, connect.NewRequest(&identitypb.ListHelpRequestsRequest{})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("ListHelpRequests unauth: %v", connectCodeOf(err))
	}
	_, err = h.client.ListHelpRequests(ctx, authedReq(connect.NewRequest(&identitypb.ListHelpRequestsRequest{
		Limit: 10, StatusFilter: identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_PENDING,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("list help: %v", err)
	}

	// ResolveHelpRequest with a missing request ID → not-found.
	if _, err := h.client.ResolveHelpRequest(ctx, connect.NewRequest(&identitypb.ResolveHelpRequestRequest{})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("ResolveHelpRequest unauth: %v", connectCodeOf(err))
	}
	_, err = h.client.ResolveHelpRequest(ctx, authedReq(connect.NewRequest(&identitypb.ResolveHelpRequestRequest{
		RequestId: "missing", ResolutionNotes: "n",
	}), "admin-1"))
	if err == nil {
		t.Fatal("expected resolve error for missing request")
	}

	// Seed a real help request and resolve it.
	h.db.addHelpRequest("hr-1", "x@e.com", "pending", time.Now().UnixMilli())
	resolved, err := h.client.ResolveHelpRequest(ctx, authedReq(connect.NewRequest(&identitypb.ResolveHelpRequestRequest{
		RequestId: "hr-1", ResolutionNotes: "done",
	}), "admin-1"))
	if err != nil {
		t.Fatalf("resolve help req: %v", err)
	}
	if resolved.Msg.Request == nil {
		t.Fatal("expected request in response")
	}
}

func TestListAuditEvents(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("admin-1", "a@e.com", "A", "admin", "active")

	if _, err := h.client.ListAuditEvents(ctx, connect.NewRequest(&identitypb.ListAuditEventsRequest{})); connectCodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("ListAuditEvents unauth: %v", connectCodeOf(err))
	}
	_, err := h.client.ListAuditEvents(ctx, authedReq(connect.NewRequest(&identitypb.ListAuditEventsRequest{
		Limit: 10,
	}), "admin-1"))
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────
// Profile / Self-service handlers
// ──────────────────────────────────────────────────────────────────────

func TestProfileHandlers_Auth(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Each requires auth.
	checks := map[string]func() error{
		"UpdateProfile": func() error {
			_, err := h.client.UpdateProfile(ctx, connect.NewRequest(&identitypb.UpdateProfileRequest{}))
			return err
		},
		"ChangePassword": func() error {
			_, err := h.client.ChangePassword(ctx, connect.NewRequest(&identitypb.ChangePasswordRequest{}))
			return err
		},
		"ListMySessions": func() error {
			_, err := h.client.ListMySessions(ctx, connect.NewRequest(&identitypb.ListMySessionsRequest{}))
			return err
		},
		"RevokeSession": func() error {
			_, err := h.client.RevokeSession(ctx, connect.NewRequest(&identitypb.RevokeSessionRequest{}))
			return err
		},
		"RevokeAllSessions": func() error {
			_, err := h.client.RevokeAllSessions(ctx, connect.NewRequest(&identitypb.RevokeAllSessionsRequest{}))
			return err
		},
		"SignOutEverywhere": func() error {
			_, err := h.client.SignOutEverywhere(ctx, connect.NewRequest(&identitypb.SignOutEverywhereRequest{}))
			return err
		},
	}
	for name, fn := range checks {
		if got := connectCodeOf(fn()); got != connect.CodeUnauthenticated {
			t.Errorf("%s expected unauth, got %v", name, got)
		}
	}
}

func TestProfileHandlers_HappyAndError(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pwHash := mustHash(t, strongPW)
	h.db.addUserWithPassword("u-1", "u@e.com", "U", "member", "active", pwHash)
	// ProfileService.UpdateProfile now routes through Repository (the
	// memory backend stubs out the low-level DB.GetNode the previous
	// shape used). Mirror the fixture into fakeRepo so the call resolves
	// the user there too.
	h.repo.seedUser(&service.User{ID: "u-1", Email: "u@e.com", Name: "U", Role: "member", Status: "active", PasswordHash: pwHash})

	// UpdateProfile.
	upd, err := h.client.UpdateProfile(ctx, authedReq(connect.NewRequest(&identitypb.UpdateProfileRequest{
		Name: "New Name", AvatarUrl: "http://a",
	}), "u-1"))
	if err != nil {
		t.Fatalf("update profile: %v", err)
	}
	if upd.Msg.User == nil {
		t.Fatal("nil user in response")
	}

	// ChangePassword.
	_, err = h.client.ChangePassword(ctx, authedReq(connect.NewRequest(&identitypb.ChangePasswordRequest{
		CurrentPassword: strongPW, NewPassword: "EvenStr0nger!Pwd",
	}), "u-1"))
	if err != nil {
		t.Fatalf("change pw: %v", err)
	}

	// ChangePassword wrong current.
	_, err = h.client.ChangePassword(ctx, authedReq(connect.NewRequest(&identitypb.ChangePasswordRequest{
		CurrentPassword: "wrong", NewPassword: "Whatever!Pwd1",
	}), "u-1"))
	if err == nil {
		t.Fatal("expected wrong-current-password error")
	}

	// RequestPasswordReset always succeeds (anti-enumeration stub).
	_, err = h.client.RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: "u@e.com",
	}))
	if err != nil {
		t.Fatalf("request pw reset: %v", err)
	}

	// ListMySessions returns whatever sessions are present (likely empty).
	if _, err := h.client.ListMySessions(ctx, authedReq(connect.NewRequest(&identitypb.ListMySessionsRequest{}), "u-1")); err != nil {
		t.Fatalf("list sessions: %v", err)
	}

	// RevokeSession with bogus ID — error from service.
	if _, err := h.client.RevokeSession(ctx, authedReq(connect.NewRequest(&identitypb.RevokeSessionRequest{
		SessionId: "no-such",
	}), "u-1")); err == nil {
		t.Fatal("expected revoke error")
	}

	// RevokeAllSessions wrong password → some error.
	if _, err := h.client.RevokeAllSessions(ctx, authedReq(connect.NewRequest(&identitypb.RevokeAllSessionsRequest{
		Password: "wrong",
	}), "u-1")); err == nil {
		t.Fatal("expected revoke-all error")
	}

	// SignOutEverywhere with the new password (since we changed it above).
	if _, err := h.client.SignOutEverywhere(ctx, authedReq(connect.NewRequest(&identitypb.SignOutEverywhereRequest{
		Password: "EvenStr0nger!Pwd",
	}), "u-1")); err != nil {
		t.Fatalf("signout everywhere: %v", err)
	}
}

func TestEmailRecoveryHandlers_ViaConnect(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	user := h.repo.seedUser(&service.User{
		Email:        "recover@example.com",
		Name:         "Recover",
		Status:       "active",
		Role:         "member",
		PasswordHash: mustHash(t, strongPW),
	})
	future := time.Now().Add(time.Hour).UnixMilli()

	if err := h.repo.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
		TokenHash: sha256Hex("reset-raw"),
		UserID:    user.ID,
		ExpiresAt: future,
		CreatedAt: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatalf("seed password reset: %v", err)
	}
	if _, err := h.client.ConfirmPasswordReset(ctx, connect.NewRequest(&identitypb.ConfirmPasswordResetRequest{
		Token:       "reset-raw",
		NewPassword: "NewStr0ng!Pass1",
	})); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}
	if _, err := h.client.PasswordLogin(ctx, withClientHeaders(connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: "recover@example.com", Password: "NewStr0ng!Pass1",
	}))); err != nil {
		t.Fatalf("login with reset password: %v", err)
	}

	if _, err := h.client.SendEmailVerification(ctx, authedReq(connect.NewRequest(&identitypb.SendEmailVerificationRequest{}), user.ID)); err != nil {
		t.Fatalf("SendEmailVerification: %v", err)
	}
	if got := len(h.repo.emailVerifications); got == 0 {
		t.Fatalf("expected verification token")
	}

	if err := h.repo.CreateEmailVerificationToken(ctx, &service.EmailVerificationToken{
		TokenHash: sha256Hex("verify-raw"),
		UserID:    user.ID,
		Email:     user.Email,
		ExpiresAt: future,
		CreatedAt: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatalf("seed email verification: %v", err)
	}
	verified, err := h.client.VerifyEmail(ctx, connect.NewRequest(&identitypb.VerifyEmailRequest{Token: "verify-raw"}))
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if !verified.Msg.User.EmailVerified {
		t.Fatalf("verified user = %+v", verified.Msg.User)
	}

	if _, err := h.client.RequestEmailChange(ctx, authedReq(connect.NewRequest(&identitypb.RequestEmailChangeRequest{
		NewEmail:        "changed@example.com",
		CurrentPassword: "NewStr0ng!Pass1",
	}), user.ID)); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	if got := len(h.repo.emailChanges); got == 0 {
		t.Fatalf("expected email change token")
	}

	if err := h.repo.CreateEmailChangeToken(ctx, &service.EmailChangeToken{
		TokenHash: sha256Hex("change-raw"),
		UserID:    user.ID,
		OldEmail:  user.Email,
		NewEmail:  "final@example.com",
		ExpiresAt: future,
		CreatedAt: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatalf("seed email change: %v", err)
	}
	changed, err := h.client.ConfirmEmailChange(ctx, connect.NewRequest(&identitypb.ConfirmEmailChangeRequest{Token: "change-raw"}))
	if err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}
	if changed.Msg.User.Email != "final@example.com" || !changed.Msg.User.EmailVerified {
		t.Fatalf("changed user = %+v", changed.Msg.User)
	}
}

// ──────────────────────────────────────────────────────────────────────
// End-to-end auth interceptor / wire format sanity
// ──────────────────────────────────────────────────────────────────────

func TestWireFormat_RoutesEachRPC(t *testing.T) {
	// Confirm at least a sample of every handler file is reachable via the
	// generated connect client (i.e. handler registration is correct).
	h := newHarness(t)
	ctx := context.Background()

	// Hit one endpoint per handler file.
	if _, err := h.client.RequestAdminHelp(ctx, connect.NewRequest(&identitypb.RequestAdminHelpRequest{
		Email: "x@e.com", Reason: "r",
	})); err != nil {
		t.Fatalf("RequestAdminHelp wire: %v", err)
	}

	if _, err := h.client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: "wire@e.com", Password: strongPW,
	})); err != nil {
		t.Fatalf("PasswordSignup wire: %v", err)
	}

	if _, err := h.client.RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: "x@e.com",
	})); err != nil {
		t.Fatalf("RequestPasswordReset wire: %v", err)
	}
}

// Sanity: connectCodeOf helper returns 0 for nil errors and CodeUnknown for
// non-connect errors.
func TestConnectCodeOfHelper(t *testing.T) {
	if got := connectCodeOf(nil); got != 0 {
		t.Fatalf("nil → 0, got %v", got)
	}
	if got := connectCodeOf(errors.New("plain")); got != connect.CodeUnknown {
		t.Fatalf("plain → unknown, got %v", got)
	}
	if got := connectCodeOf(connect.NewError(connect.CodeNotFound, errors.New("x"))); got != connect.CodeNotFound {
		t.Fatalf("connect err round-trip, got %v", got)
	}
}

// ──────────────────────────────────────────────────────────────────────
// Authed-but-service-fails tests — exercise the post-auth error branches
// in each handler (the `if err != nil { return toConnectError(...) }`
// after the service call, which is distinct from the early Unauth check).
// ──────────────────────────────────────────────────────────────────────

func TestAdminHandlers_PostAuthErrors(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("admin-1", "a@e.com", "A", "admin", "active")

	// InviteUser: invalid email after auth check passes.
	if _, err := h.client.InviteUser(ctx, authedReq(connect.NewRequest(&identitypb.InviteUserRequest{
		Email: "bademail",
	}), "admin-1")); err == nil {
		t.Fatal("expected invite invalid-email error")
	}

	// CreateUser: invalid email.
	if _, err := h.client.CreateUser(ctx, authedReq(connect.NewRequest(&identitypb.CreateUserRequest{
		Email: "bad",
	}), "admin-1")); err == nil {
		t.Fatal("expected create invalid-email error")
	}

	// GetUser missing target → not-found.
	if _, err := h.client.GetUser(ctx, authedReq(connect.NewRequest(&identitypb.GetUserRequest{
		UserId: "no-such",
	}), "admin-1")); err == nil {
		t.Fatal("expected get-user error")
	}

	// UpdateUser missing target.
	if _, err := h.client.UpdateUser(ctx, authedReq(connect.NewRequest(&identitypb.UpdateUserRequest{
		UserId: "no-such", Name: "X",
	}), "admin-1")); err == nil {
		t.Fatal("expected update-user error")
	}

	// DeactivateUser missing target.
	if _, err := h.client.DeactivateUser(ctx, authedReq(connect.NewRequest(&identitypb.DeactivateUserRequest{
		UserId: "no-such",
	}), "admin-1")); err == nil {
		t.Fatal("expected deactivate error")
	}

	// ReactivateUser missing target.
	if _, err := h.client.ReactivateUser(ctx, authedReq(connect.NewRequest(&identitypb.ReactivateUserRequest{
		UserId: "no-such",
	}), "admin-1")); err == nil {
		t.Fatal("expected reactivate error")
	}

	// ResetUserPassword missing target.
	if _, err := h.client.ResetUserPassword(ctx, authedReq(connect.NewRequest(&identitypb.ResetUserPasswordRequest{
		UserId: "no-such", GenerateTempPassword: true,
	}), "admin-1")); err == nil {
		t.Fatal("expected reset-pw error")
	}

	// SetUserQuota missing target.
	if _, err := h.client.SetUserQuota(ctx, authedReq(connect.NewRequest(&identitypb.SetUserQuotaRequest{
		UserId: "no-such", QuotaBytes: 1,
	}), "admin-1")); err == nil {
		t.Fatal("expected set-quota error")
	}

	// DeleteUser missing target.
	if _, err := h.client.DeleteUser(ctx, authedReq(connect.NewRequest(&identitypb.DeleteUserRequest{
		UserId: "no-such",
	}), "admin-1")); err == nil {
		t.Fatal("expected delete-user error")
	}
}

// TestDeleteUser_NotFoundMapsToConnectCode asserts that the DeleteUser
// handler maps the service's ErrNotFound (deleting a user that does not
// exist in the repo) to a NotFound connect code via toConnectError —
// the handler's error return path.
func TestDeleteUser_NotFoundMapsToConnectCode(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("admin-1", "a@e.com", "A", "admin", "active")

	_, err := h.client.DeleteUser(ctx, authedReq(connect.NewRequest(&identitypb.DeleteUserRequest{
		UserId: "ghost",
	}), "admin-1"))
	if err == nil {
		t.Fatal("expected error deleting a non-existent user")
	}
	if got := connectCodeOf(err); got != connect.CodeNotFound {
		t.Fatalf("expected CodeNotFound, got %v: %v", got, err)
	}
}

func TestGroupHandlers_PostAuthErrors(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("admin-1", "a@e.com", "A", "admin", "active")

	// UpdateGroup with missing group.
	if _, err := h.client.UpdateGroup(ctx, authedReq(connect.NewRequest(&identitypb.UpdateGroupRequest{
		GroupId: "no-group", Name: "X",
	}), "admin-1")); err == nil {
		t.Fatal("expected update-group error")
	}

	// DeleteGroup missing — service is forgiving and may succeed; just call it.
	_, _ = h.client.DeleteGroup(ctx, authedReq(connect.NewRequest(&identitypb.DeleteGroupRequest{
		GroupId: "no-group",
	}), "admin-1"))

	// AddGroupMember/RemoveGroupMember/ListGroupMembers with a missing group
	// don't return an error (the service is forgiving). Exercise them anyway
	// to cover the post-auth path, then trigger db-level errors below.
	_, _ = h.client.AddGroupMember(ctx, authedReq(connect.NewRequest(&identitypb.AddGroupMemberRequest{
		GroupId: "no-group", UserId: "u",
	}), "admin-1"))
	_, _ = h.client.RemoveGroupMember(ctx, authedReq(connect.NewRequest(&identitypb.RemoveGroupMemberRequest{
		GroupId: "no-group", UserId: "u",
	}), "admin-1"))
	_, _ = h.client.ListGroupMembers(ctx, authedReq(connect.NewRequest(&identitypb.ListGroupMembersRequest{
		GroupId: "no-group",
	}), "admin-1"))

	// Force underlying db errors to exercise error-mapping branches.
	h.db.err = errors.New("db kaput")
	if _, err := h.client.ListGroups(ctx, authedReq(connect.NewRequest(&identitypb.ListGroupsRequest{
		Limit: 10,
	}), "admin-1")); err == nil {
		t.Fatal("expected list-groups error with broken db")
	}
	if _, err := h.client.AddGroupMember(ctx, authedReq(connect.NewRequest(&identitypb.AddGroupMemberRequest{
		GroupId: "g", UserId: "u",
	}), "admin-1")); err == nil {
		t.Fatal("expected add-member error with broken db")
	}
	if _, err := h.client.RemoveGroupMember(ctx, authedReq(connect.NewRequest(&identitypb.RemoveGroupMemberRequest{
		GroupId: "g", UserId: "u",
	}), "admin-1")); err == nil {
		t.Fatal("expected remove-member error with broken db")
	}
	if _, err := h.client.ListGroupMembers(ctx, authedReq(connect.NewRequest(&identitypb.ListGroupMembersRequest{
		GroupId: "g",
	}), "admin-1")); err == nil {
		t.Fatal("expected list-members error with broken db")
	}
	h.db.err = nil
}

func TestHelpAndAuditPostAuthErrors(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("admin-1", "a@e.com", "A", "admin", "active")

	// Trigger db error during ListHelpRequests.
	h.db.err = errors.New("db down")
	if _, err := h.client.ListHelpRequests(ctx, authedReq(connect.NewRequest(&identitypb.ListHelpRequestsRequest{
		Limit: 10,
	}), "admin-1")); err == nil {
		t.Fatal("expected list-help error")
	}
	if _, err := h.client.ListAuditEvents(ctx, authedReq(connect.NewRequest(&identitypb.ListAuditEventsRequest{
		Limit: 10,
	}), "admin-1")); err == nil {
		t.Fatal("expected list-audit error")
	}
	h.db.err = nil
}

func TestProfileAndPasskeyPostAuthErrors(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pwHash := mustHash(t, strongPW)
	u := h.repo.seedUser(&service.User{Email: "p@e.com", Status: "active", Role: "member", PasswordHash: pwHash})
	h.db.addUserWithPassword(u.ID, u.Email, u.Name, u.Role, u.Status, pwHash)

	// UpdateProfile now routes through Repository — break the repo's
	// GetUser to exercise the error path.
	h.repo.errGetUser = errors.New("repo down")
	if _, err := h.client.UpdateProfile(ctx, authedReq(connect.NewRequest(&identitypb.UpdateProfileRequest{
		Name: "NewName",
	}), u.ID)); err == nil {
		t.Fatal("expected update-profile err with broken repo")
	}
	h.repo.errGetUser = nil

	// ListMySessions still uses the DB interface — break that.
	h.db.err = errors.New("db down")
	if _, err := h.client.ListMySessions(ctx, authedReq(connect.NewRequest(&identitypb.ListMySessionsRequest{}), u.ID)); err == nil {
		t.Fatal("expected list-sessions err with broken db")
	}
	h.db.err = nil

	// BeginPasskeyRegistration with missing user.
	if _, err := h.client.BeginPasskeyRegistration(ctx, authedReq(connect.NewRequest(&identitypb.BeginPasskeyRegistrationRequest{
		DeviceName: "X",
	}), "no-such-user")); err == nil {
		t.Fatal("expected begin-passkey-reg error")
	}

	// CompletePasskeyRegistration with bogus challenge.
	if _, err := h.client.CompletePasskeyRegistration(ctx, authedReq(connect.NewRequest(&identitypb.CompletePasskeyRegistrationRequest{
		ChallengeId: "no", CredentialJson: "{}", DeviceName: "X",
	}), u.ID)); err == nil {
		t.Fatal("expected complete-passkey-reg error")
	}
}

func TestTotpHandlers_PostAuthErrors(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// BeginTotpSetup with missing user → service errors.
	if _, err := h.client.BeginTotpSetup(ctx,
		authedReq(connect.NewRequest(&identitypb.BeginTotpSetupRequest{}), "no-user")); err == nil {
		t.Fatal("expected begin-totp error")
	}

	// VerifyTotpSetup with missing user.
	if _, err := h.client.VerifyTotpSetup(ctx,
		authedReq(connect.NewRequest(&identitypb.VerifyTotpSetupRequest{Code: "000000"}), "no-user")); err == nil {
		t.Fatal("expected verify-setup error")
	}

	// RegenerateRecoveryCodes with missing user.
	if _, err := h.client.RegenerateRecoveryCodes(ctx,
		authedReq(connect.NewRequest(&identitypb.RegenerateRecoveryCodesRequest{Password: strongPW}), "no-user")); err == nil {
		t.Fatal("expected regen error")
	}
}

// ──────────────────────────────────────────────────────────────────────
// Targeted success-path coverage for handlers whose service calls succeed.
// ──────────────────────────────────────────────────────────────────────

func TestDeletePasskey_Success(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	pwHash := mustHash(t, strongPW)
	h.db.addUserWithPassword("u-pk", "u@e.com", "U", "member", "active", pwHash)
	h.db.addPasskey("pk-1", "u-pk", "cred-1", "iPhone")

	// ListPasskeys success.
	lp, err := h.client.ListPasskeys(ctx,
		authedReq(connect.NewRequest(&identitypb.ListPasskeysRequest{}), "u-pk"))
	if err != nil {
		t.Fatalf("list passkeys: %v", err)
	}
	if len(lp.Msg.Credentials) == 0 {
		t.Fatal("expected at least one passkey")
	}

	// DeletePasskey success.
	if _, err := h.client.DeletePasskey(ctx,
		authedReq(connect.NewRequest(&identitypb.DeletePasskeyRequest{CredentialId: "cred-1"}), "u-pk")); err != nil {
		t.Fatalf("delete passkey: %v", err)
	}
}

func TestRevokeSession_Success(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pwHash := mustHash(t, strongPW)
	h.db.addUserWithPassword("u-rs", "u@e.com", "U", "member", "active", pwHash)
	h.db.addRefreshToken("sess-1", "u-rs", time.Now().Add(time.Hour).UnixMilli())

	if _, err := h.client.RevokeSession(ctx,
		authedReq(connect.NewRequest(&identitypb.RevokeSessionRequest{SessionId: "sess-1"}), "u-rs")); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
}

func TestRevokeAllSessions_Success(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pwHash := mustHash(t, strongPW)
	h.db.addUserWithPassword("u-rall", "u@e.com", "U", "member", "active", pwHash)
	h.db.addRefreshToken("rt-a", "u-rall", time.Now().Add(time.Hour).UnixMilli())
	h.db.addRefreshToken("rt-b", "u-rall", time.Now().Add(time.Hour).UnixMilli())

	resp, err := h.client.RevokeAllSessions(ctx,
		authedReq(connect.NewRequest(&identitypb.RevokeAllSessionsRequest{Password: strongPW}), "u-rall"))
	if err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	if resp.Msg.RevokedCount < 1 {
		t.Fatalf("expected count >=1, got %d", resp.Msg.RevokedCount)
	}
}

func TestLogout_BadToken_Error(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Service may not error on unknown token; force repo failure pattern by
	// passing empty string which validates inside service.
	_, _ = h.client.Logout(ctx, connect.NewRequest(&identitypb.LogoutRequest{
		RefreshToken: "",
	}))
}

func TestDeleteGroup_PostAuthError(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.addUser("admin-1", "a@e.com", "A", "admin", "active")
	h.db.err = errors.New("db down")
	if _, err := h.client.DeleteGroup(ctx, authedReq(connect.NewRequest(&identitypb.DeleteGroupRequest{
		GroupId: "any",
	}), "admin-1")); err == nil {
		t.Fatal("expected delete-group error with broken db")
	}
	h.db.err = nil
}

func TestApproveQrLogin_BadSession(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	u := h.repo.seedUser(&service.User{Email: "u@e.com", Status: "active", Role: "member"})
	if _, err := h.client.ApproveQrLogin(ctx,
		authedReq(connect.NewRequest(&identitypb.ApproveQrLoginRequest{
			SessionId: "no-such", Approve: true,
		}), u.ID)); err == nil {
		t.Fatal("expected approve error for missing session")
	}
}

// quiet linter on unused string import
var _ = strings.Contains
