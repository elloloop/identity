//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
)

// extractLoginCode pulls the 6-digit OTP out of a code email's text body.
func extractLoginCode(t *testing.T, body string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		s := strings.TrimSpace(line)
		if len(s) == 6 {
			allDigits := true
			for _, r := range s {
				if r < '0' || r > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return s
			}
		}
	}
	t.Fatalf("no 6-digit code in body: %q", body)
	return ""
}

// TestPasswordless_EmailCode_RequestVerifyTokens drives the full OTP arm
// end to end against the configured backend: request → verify → tokens,
// then asserts replay of the same code is rejected.
func TestPasswordless_EmailCode_RequestVerifyTokens(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()
	const addr = "otp-flow@test.com"

	_, err := h.Client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: addr}))
	if err != nil {
		t.Fatalf("RequestEmailLoginCode: %v", err)
	}
	sent := h.Mailer.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 code email, got %d", len(sent))
	}
	code := extractLoginCode(t, sent[0].Text)

	resp, err := h.Client.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{
		Email: addr, Code: code,
	}))
	if err != nil {
		t.Fatalf("VerifyEmailLoginCode: %v", err)
	}
	if resp.Msg.AccessToken == "" || resp.Msg.RefreshToken == "" {
		t.Fatalf("verify returned empty tokens")
	}
	if got := resp.Msg.GetUser().GetEmail(); got != addr {
		t.Fatalf("user email = %q, want %q", got, addr)
	}

	// Replay: the same code must be rejected (single-use).
	_, err = h.Client.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{
		Email: addr, Code: code,
	}))
	if err == nil {
		t.Fatal("replay of consumed code: want error, got nil")
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("replay error code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

// TestPasswordless_MagicLink_RequestRedeemTokens drives the magic-link arm
// end to end and asserts single-use replay rejection.
func TestPasswordless_MagicLink_RequestRedeemTokens(t *testing.T) {
	t.Parallel()
	h := StartServer(t, WithConfig(func(c *config.Config) {
		c.OAuthAllowedReturnURLs = "https://app.test/"
	}))
	ctx := context.Background()
	const addr = "ml-flow@test.com"

	_, err := h.Client.RequestMagicLink(ctx, connect.NewRequest(&identitypb.RequestMagicLinkRequest{
		Email: addr, ReturnTo: "https://app.test/done",
	}))
	if err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	sent := h.Mailer.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 magic-link email, got %d", len(sent))
	}
	token := extractToken(t, sent[0].Text)

	resp, err := h.Client.RedeemMagicLink(ctx, connect.NewRequest(&identitypb.RedeemMagicLinkRequest{Token: token}))
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if resp.Msg.AccessToken == "" || resp.Msg.RefreshToken == "" {
		t.Fatalf("redeem returned empty tokens")
	}
	if got := resp.Msg.GetReturnTo(); got != "https://app.test/done" {
		t.Fatalf("return_to = %q, want https://app.test/done", got)
	}

	// Replay rejected.
	_, err = h.Client.RedeemMagicLink(ctx, connect.NewRequest(&identitypb.RedeemMagicLinkRequest{Token: token}))
	if err == nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("replay redeem: want Unauthenticated, got %v", err)
	}
}

// TestPasswordless_LinksToPasswordAccount is the unified-account guarantee
// against a real backend: sign up via password, then log in passwordless
// (both arms) and assert the SAME user id — no duplicate account.
func TestPasswordless_LinksToPasswordAccount(t *testing.T) {
	t.Parallel()
	h := StartServer(t, WithConfig(func(c *config.Config) {
		c.OAuthAllowedReturnURLs = "https://app.test/"
	}))
	ctx := context.Background()
	const addr = "unified@test.com"

	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: "Sw0rdfish!42",
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	pwUserID := signup.Msg.GetUser().GetId()
	h.Mailer.Reset()

	// OTP arm resolves to the same account.
	if _, err := h.Client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: addr})); err != nil {
		t.Fatalf("RequestEmailLoginCode: %v", err)
	}
	code := extractLoginCode(t, h.Mailer.Sent()[0].Text)
	otp, err := h.Client.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{Email: addr, Code: code}))
	if err != nil {
		t.Fatalf("VerifyEmailLoginCode: %v", err)
	}
	if got := otp.Msg.GetUser().GetId(); got != pwUserID {
		t.Fatalf("OTP login user id = %q, want %q (must link, not duplicate)", got, pwUserID)
	}

	h.Mailer.Reset()
	// Magic-link arm resolves to the same account.
	if _, err := h.Client.RequestMagicLink(ctx, connect.NewRequest(&identitypb.RequestMagicLinkRequest{
		Email: addr, ReturnTo: "https://app.test/done",
	})); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	token := extractToken(t, h.Mailer.Sent()[0].Text)
	ml, err := h.Client.RedeemMagicLink(ctx, connect.NewRequest(&identitypb.RedeemMagicLinkRequest{Token: token}))
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if got := ml.Msg.GetUser().GetId(); got != pwUserID {
		t.Fatalf("magic-link login user id = %q, want %q (must link, not duplicate)", got, pwUserID)
	}
}

// TestPasswordless_EmailCode_PerEmailCooldown asserts the per-email send
// cooldown so a single inbox cannot be flooded.
func TestPasswordless_EmailCode_PerEmailCooldown(t *testing.T) {
	t.Parallel()
	h := StartServer(t, WithConfig(func(c *config.Config) {
		c.EmailSendCooldownSeconds = 3600
	}))
	ctx := context.Background()
	const addr = "cooldown@test.com"

	for i := 0; i < 3; i++ {
		if _, err := h.Client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: addr})); err != nil {
			t.Fatalf("RequestEmailLoginCode %d: %v", i, err)
		}
	}
	if got := len(h.Mailer.Sent()); got != 1 {
		t.Fatalf("per-email cooldown: sent %d emails, want 1", got)
	}
}
