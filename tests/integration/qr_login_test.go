//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
)

func TestQrLogin_HappyPath(t *testing.T) {
	t.Parallel()

	h := StartServer(t)
	ctx := context.Background()

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "qr-approve@example.com",
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	initiate, err := h.Client.InitiateQrLogin(ctx, newReq(&identitypb.InitiateQrLoginRequest{
		DeviceInfo: "Pixel 8",
		UserAgent:  "Chrome Mobile",
	}, map[string]string{
		"X-Forwarded-For": "203.0.113.10",
	}))
	if err != nil {
		t.Fatalf("InitiateQrLogin: %v", err)
	}
	if initiate.Msg.SessionId == "" {
		t.Fatalf("expected QR session id")
	}
	if !strings.Contains(initiate.Msg.QrUrl, initiate.Msg.SessionId) {
		t.Fatalf("qr url %q does not contain session id %q", initiate.Msg.QrUrl, initiate.Msg.SessionId)
	}

	pending, err := h.Client.PollQrLogin(ctx, newReq(&identitypb.PollQrLoginRequest{
		SessionId: initiate.Msg.SessionId,
	}, map[string]string{
		"X-Forwarded-For": "203.0.113.10",
		"User-Agent":      "Chrome Mobile",
	}))
	if err != nil {
		t.Fatalf("PollQrLogin pending: %v", err)
	}
	if pending.Msg.Status != identitypb.QrLoginStatus_QR_LOGIN_STATUS_PENDING {
		t.Fatalf("pending status = %v, want PENDING", pending.Msg.Status)
	}

	approver := h.AuthedClient(signup.Msg.AccessToken)
	approved, err := approver.ApproveQrLogin(ctx, newReq(&identitypb.ApproveQrLoginRequest{
		SessionId: initiate.Msg.SessionId,
		Approve:   true,
	}, map[string]string{
		"User-Agent": "Safari on Mac",
	}))
	if err != nil {
		t.Fatalf("ApproveQrLogin: %v", err)
	}
	if approved.Msg.Status != identitypb.QrLoginStatus_QR_LOGIN_STATUS_APPROVED {
		t.Fatalf("approve status = %v, want APPROVED", approved.Msg.Status)
	}

	poll, err := h.Client.PollQrLogin(ctx, newReq(&identitypb.PollQrLoginRequest{
		SessionId: initiate.Msg.SessionId,
	}, map[string]string{
		"X-Forwarded-For": "203.0.113.10",
		"User-Agent":      "Chrome Mobile",
	}))
	if err != nil {
		t.Fatalf("PollQrLogin approved: %v", err)
	}
	if poll.Msg.Status != identitypb.QrLoginStatus_QR_LOGIN_STATUS_APPROVED {
		t.Fatalf("approved poll status = %v, want APPROVED", poll.Msg.Status)
	}
	if poll.Msg.AccessToken == "" || poll.Msg.RefreshToken == "" {
		t.Fatalf("expected approved poll to mint tokens")
	}
	if got := poll.Msg.GetUser().GetId(); got != signup.Msg.GetUser().GetId() {
		t.Fatalf("poll user id = %q, want %q", got, signup.Msg.GetUser().GetId())
	}

	consumed, err := h.Client.PollQrLogin(ctx, connect.NewRequest(&identitypb.PollQrLoginRequest{
		SessionId: initiate.Msg.SessionId,
	}))
	if err != nil {
		t.Fatalf("PollQrLogin consumed: %v", err)
	}
	if consumed.Msg.Status != identitypb.QrLoginStatus_QR_LOGIN_STATUS_CONSUMED {
		t.Fatalf("consumed status = %v, want CONSUMED", consumed.Msg.Status)
	}
}

func TestQrLogin_RejectPath(t *testing.T) {
	t.Parallel()

	h := StartServer(t)
	ctx := context.Background()

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "qr-reject@example.com",
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	initiate, err := h.Client.InitiateQrLogin(ctx, connect.NewRequest(&identitypb.InitiateQrLoginRequest{
		DeviceInfo: "iPad",
		UserAgent:  "Mobile Safari",
	}))
	if err != nil {
		t.Fatalf("InitiateQrLogin: %v", err)
	}

	approver := h.AuthedClient(signup.Msg.AccessToken)
	rejected, err := approver.ApproveQrLogin(ctx, connect.NewRequest(&identitypb.ApproveQrLoginRequest{
		SessionId: initiate.Msg.SessionId,
		Approve:   false,
	}))
	if err != nil {
		t.Fatalf("ApproveQrLogin reject: %v", err)
	}
	if rejected.Msg.Status != identitypb.QrLoginStatus_QR_LOGIN_STATUS_REJECTED {
		t.Fatalf("reject status = %v, want REJECTED", rejected.Msg.Status)
	}

	poll, err := h.Client.PollQrLogin(ctx, connect.NewRequest(&identitypb.PollQrLoginRequest{
		SessionId: initiate.Msg.SessionId,
	}))
	if err != nil {
		t.Fatalf("PollQrLogin rejected: %v", err)
	}
	if poll.Msg.Status != identitypb.QrLoginStatus_QR_LOGIN_STATUS_REJECTED {
		t.Fatalf("rejected poll status = %v, want REJECTED", poll.Msg.Status)
	}
}

func TestQrLogin_ExpiryPath(t *testing.T) {
	t.Parallel()

	h := StartServer(t)
	ctx := context.Background()

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    "qr-expired@example.com",
		Password: goodPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	initiate, err := h.Client.InitiateQrLogin(ctx, connect.NewRequest(&identitypb.InitiateQrLoginRequest{
		DeviceInfo: "Linux workstation",
		UserAgent:  "Firefox",
	}))
	if err != nil {
		t.Fatalf("InitiateQrLogin: %v", err)
	}

	expireQrLoginSession(t, h.Repo, initiate.Msg.SessionId)

	approver := h.AuthedClient(signup.Msg.AccessToken)

	session, err := approver.GetQrLoginSession(ctx, connect.NewRequest(&identitypb.GetQrLoginSessionRequest{
		SessionId: initiate.Msg.SessionId,
	}))
	if err != nil {
		t.Fatalf("GetQrLoginSession: %v", err)
	}
	if session.Msg.Status != identitypb.QrLoginStatus_QR_LOGIN_STATUS_EXPIRED {
		t.Fatalf("session status = %v, want EXPIRED", session.Msg.Status)
	}

	_, err = approver.ApproveQrLogin(ctx, connect.NewRequest(&identitypb.ApproveQrLoginRequest{
		SessionId: initiate.Msg.SessionId,
		Approve:   true,
	}))
	if err == nil {
		t.Fatalf("expected expired approval to fail")
	}
	if got := connect.CodeOf(err); got != connect.CodeDeadlineExceeded {
		t.Fatalf("approve expired code = %v, want DeadlineExceeded (err=%v)", got, err)
	}

	poll, err := h.Client.PollQrLogin(ctx, connect.NewRequest(&identitypb.PollQrLoginRequest{
		SessionId: initiate.Msg.SessionId,
	}))
	if err != nil {
		t.Fatalf("PollQrLogin expired: %v", err)
	}
	if poll.Msg.Status != identitypb.QrLoginStatus_QR_LOGIN_STATUS_EXPIRED {
		t.Fatalf("poll status = %v, want EXPIRED", poll.Msg.Status)
	}
}
