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

const (
	hubBase          = "https://accounts.test"
	hubReturnTo      = "https://tortoise.test/after?step=2"
	hubReturnToQuery = "https%3A%2F%2Ftortoise.test%2Fafter%3Fstep%3D2"
)

// startHubServer serves a deployment whose reset and verification pages live
// on a sign-in hub (GATEWAY_EMAIL_LINK_BASE_URL) and that trusts the tortoise
// app as a return URL (GATEWAY_OAUTH_ALLOWED_RETURN_URLS).
func startHubServer(t *testing.T) *Harness {
	t.Helper()
	return StartServer(t, WithConfig(func(cfg *config.Config) {
		cfg.EmailLinkBaseURL = hubBase
		cfg.OAuthAllowedReturnURLs = "https://tortoise.test"
	}))
}

// linkIn returns the link in a plain-text email body that starts with prefix,
// up to the next whitespace.
func linkIn(t *testing.T, body, prefix string) string {
	t.Helper()
	idx := strings.Index(body, prefix)
	if idx == -1 {
		t.Fatalf("no link starting %q in body: %q", prefix, body)
	}
	link := body[idx:]
	if end := strings.IndexAny(link, " \r\n"); end != -1 {
		link = link[:end]
	}
	return link
}

// TestEmailLink_HubBase_LinksCarryProductAndRedirect drives every RPC that
// emails a reset or verification link over the wire against a hub deployment:
// each link lands on the hub page, names the product and carries the
// URL-encoded return_to, and its token redeems through identity's RPCs.
func TestEmailLink_HubBase_LinksCarryProductAndRedirect(t *testing.T) {
	t.Parallel()
	h := startHubServer(t)
	ctx := context.Background()

	const addr = "parent@test.com"
	const newPW = "Newp@ssw0rd!99"
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: "Sw0rdfish!42", Product: "Tortoise", ReturnTo: hubReturnTo,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	assertHubLink(t, h, "verify-email")

	if _, err := h.AuthedClient(signup.Msg.AccessToken).SendEmailVerification(ctx,
		connect.NewRequest(&identitypb.SendEmailVerificationRequest{Product: "tortoise", ReturnTo: hubReturnTo})); err != nil {
		t.Fatalf("SendEmailVerification: %v", err)
	}
	tok := assertHubLink(t, h, "verify-email")
	if _, err := h.Client.VerifyEmail(ctx, connect.NewRequest(&identitypb.VerifyEmailRequest{Token: tok})); err != nil {
		t.Fatalf("VerifyEmail with the hub link's token: %v", err)
	}

	if _, err := h.Client.RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: addr, Product: "tortoise", ReturnTo: hubReturnTo,
	})); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	tok = assertHubLink(t, h, "reset-password")
	if _, err := h.Client.ConfirmPasswordReset(ctx, connect.NewRequest(&identitypb.ConfirmPasswordResetRequest{
		Token: tok, NewPassword: newPW,
	})); err != nil {
		t.Fatalf("ConfirmPasswordReset with the hub link's token: %v", err)
	}
	if _, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: addr, Password: newPW,
	})); err != nil {
		t.Fatalf("login with the reset password: %v", err)
	}
}

// assertHubLink checks the one email sent since the last call links to page on
// the hub with the product and the encoded return_to, and returns its token.
func assertHubLink(t *testing.T, h *Harness, page string) string {
	t.Helper()
	sent := h.Mailer.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 email for %s, got %d", page, len(sent))
	}
	h.Mailer.Reset()
	tok := extractToken(t, sent[0].Text)
	want := hubBase + "/" + page + "?token=" + tok + "&product=tortoise&redirect=" + hubReturnToQuery
	if got := linkIn(t, sent[0].Text, hubBase); got != want {
		t.Fatalf("%s link:\n got  %s\n want %s", page, got, want)
	}
	return tok
}

// TestEmailLink_RefusedReturnTo_InvalidArgumentAndNothingSent: a return_to
// off the allowlist is refused with InvalidArgument on every RPC — for a
// password reset, identically whether or not the address has an account —
// and no email goes out.
func TestEmailLink_RefusedReturnTo_InvalidArgumentAndNothingSent(t *testing.T) {
	t.Parallel()
	h := startHubServer(t)
	ctx := context.Background()

	const addr = "known@test.com"
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: "Sw0rdfish!42",
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	h.Mailer.Reset()

	const evil = "https://evil.test/phish"
	for _, email := range []string{addr, "unknown@test.com"} {
		_, err := h.Client.RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{
			Email: email, ReturnTo: evil,
		}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("RequestPasswordReset(%s): %v, want InvalidArgument", email, err)
		}
	}
	_, err = h.AuthedClient(signup.Msg.AccessToken).SendEmailVerification(ctx,
		connect.NewRequest(&identitypb.SendEmailVerificationRequest{ReturnTo: evil}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("SendEmailVerification: %v, want InvalidArgument", err)
	}
	_, err = h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: "fresh@test.com", Password: "Sw0rdfish!42", ReturnTo: evil,
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("PasswordSignup: %v, want InvalidArgument", err)
	}
	if got := len(h.Mailer.Sent()); got != 0 {
		t.Fatalf("refused requests sent %d emails", got)
	}
}

// TestEmailLink_NoBase_KeepsAppAuthLink pins backward compatibility over the
// wire: with no GATEWAY_EMAIL_LINK_BASE_URL and no link params the reset link
// is exactly today's <app base>/auth/reset-password?token=<token>.
func TestEmailLink_NoBase_KeepsAppAuthLink(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	ctx := context.Background()

	const addr = "legacy@test.com"
	if _, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: "Sw0rdfish!42",
	})); err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	h.Mailer.Reset()

	if _, err := h.Client.RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: addr,
	})); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	text := h.Mailer.Sent()[0].Text
	want := "https://app.test/auth/reset-password?token=" + extractToken(t, text)
	if got := linkIn(t, text, "https://app.test/"); got != want {
		t.Fatalf("reset link = %q, want %q", got, want)
	}
}
