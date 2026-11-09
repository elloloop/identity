//go:build integration && realpostgres

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
)

const (
	serverLinkBase  = "https://signin.example.test"
	projectLinkBase = "https://signin.acme.example.test"
	projectFrom     = "no-reply@acme.example.test"
)

// TestEmailLink_ProjectBase_OverTheWire: an operator gives a project a link base
// of its own through UpsertProjectConfig, and the reset and verification links
// that project mails land there instead of on GATEWAY_EMAIL_LINK_BASE_URL, from
// the project's own sender. Each token redeems against the same project, on its
// own host, which is what the page at that base calls.
func TestEmailLink_ProjectBase_OverTheWire(t *testing.T) {
	h := startRedesignHarnessWith(t, func(cfg *config.Config) { cfg.EmailLinkBaseURL = serverLinkBase })
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)

	if _, err := admin.UpsertProjectConfig(ctx, connect.NewRequest(&identitypb.UpsertProjectConfigRequest{
		ProjectId:  h.ProjectID,
		ConfigJson: `{"access":{"mode":"open"},"branding":{"email_link_base_url":"https://signin.acme.example.test?x=1"}}`,
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("UpsertProjectConfig with a query on the link base: %v, want InvalidArgument", err)
	}
	if _, err := admin.UpsertProjectConfig(ctx, connect.NewRequest(&identitypb.UpsertProjectConfigRequest{
		ProjectId: h.ProjectID,
		ConfigJson: `{"access":{"mode":"open"},"branding":{"email_from":"` + projectFrom +
			`","email_link_base_url":"` + projectLinkBase + `/"}}`,
	})); err != nil {
		t.Fatalf("UpsertProjectConfig: %v", err)
	}

	client := h.ClientWithHost(h.BrandedAuthDomain, nil)
	const addr = "member@test.com"
	const newPW = "Newp@ssw0rd!99"
	if _, err := client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: "Sw0rdfish!42",
	})); err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	tok := assertProjectLink(t, h, "verify-email")
	if _, err := client.VerifyEmail(ctx, connect.NewRequest(&identitypb.VerifyEmailRequest{Token: tok})); err != nil {
		t.Fatalf("VerifyEmail with the project link's token: %v", err)
	}

	if _, err := client.RequestPasswordReset(ctx, connect.NewRequest(&identitypb.RequestPasswordResetRequest{
		Email: addr,
	})); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	tok = assertProjectLink(t, h, "reset-password")
	if _, err := client.ConfirmPasswordReset(ctx, connect.NewRequest(&identitypb.ConfirmPasswordResetRequest{
		Token: tok, NewPassword: newPW,
	})); err != nil {
		t.Fatalf("ConfirmPasswordReset with the project link's token: %v", err)
	}
	if _, err := client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email: addr, Password: newPW,
	})); err != nil {
		t.Fatalf("login with the reset password: %v", err)
	}
}

// assertProjectLink checks the one email sent since the last call comes from
// the project's sender and links to page on the project's base, and returns
// its token.
func assertProjectLink(t *testing.T, h *RedesignHarness, page string) string {
	t.Helper()
	sent := h.Mailer.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 email for %s, got %d", page, len(sent))
	}
	h.Mailer.Reset()
	if sent[0].From != projectFrom {
		t.Errorf("%s From = %q, want %q", page, sent[0].From, projectFrom)
	}
	tok := extractToken(t, sent[0].Text)
	want := projectLinkBase + "/" + page + "?token=" + tok
	if got := linkIn(t, sent[0].Text, "https://"); got != want {
		t.Fatalf("%s link:\n got  %s\n want %s", page, got, want)
	}
	return tok
}
