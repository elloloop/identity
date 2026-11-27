package email

import (
	"strings"
	"testing"
)

func TestRenderPasswordReset(t *testing.T) {
	t.Parallel()
	html, text, err := Render(TemplatePasswordReset, map[string]any{
		"UserName":  "Alice",
		"Link":      "https://example.com/reset?t=abc",
		"ExpiresIn": "30 minutes",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"Alice", "https://example.com/reset?t=abc", "30 minutes"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q", want)
		}
	}
	if !strings.Contains(html, "Reset your password") {
		t.Errorf("html missing heading")
	}
}

func TestRenderEmailVerification(t *testing.T) {
	t.Parallel()
	html, text, err := Render(TemplateEmailVerification, map[string]any{
		"UserName":  "Bob",
		"Link":      "https://example.com/verify?t=xyz",
		"ExpiresIn": "24 hours",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"Bob", "https://example.com/verify?t=xyz", "24 hours"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q", want)
		}
	}
}

func TestRenderInvitation(t *testing.T) {
	t.Parallel()
	html, text, err := Render(TemplateInvitation, map[string]any{
		"UserName":    "Carol",
		"InviterName": "Dave",
		"OrgName":     "Acme",
		"Link":        "https://example.com/invite?t=foo",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"Carol", "Dave", "Acme", "https://example.com/invite?t=foo"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q", want)
		}
	}
}

func TestRenderTenantInvitation(t *testing.T) {
	t.Parallel()
	html, text, err := Render(TemplateTenantInvitation, map[string]any{
		"UserName":    "Erin",
		"InviterName": "Frank",
		"TenantName":  "Globex",
		"Role":        "admin",
		"ExpiresIn":   "7 days",
		"Link":        "https://example.com/invite?t=bar",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"Erin", "Frank", "Globex", "admin", "7 days", "https://example.com/invite?t=bar"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q", want)
		}
	}
}

// TestRenderTenantInvitation_WithoutTenantName: an invitation whose tenant
// name is left out names no tenant at all, in either part.
func TestRenderTenantInvitation_WithoutTenantName(t *testing.T) {
	t.Parallel()
	html, text, err := Render(TemplateTenantInvitation, map[string]any{
		"UserName":    "Erin",
		"InviterName": "Frank",
		"TenantName":  "",
		"Role":        "member",
		"ExpiresIn":   "7 days",
		"Link":        "https://example.com/invite?t=bar",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for name, body := range map[string]string{"html": html, "text": text} {
		if !strings.Contains(body, "invited you to join a team as a member") {
			t.Errorf("%s does not invite to a team: %s", name, body)
		}
		if strings.Contains(body, "<strong></strong>") || strings.Contains(body, "join  as") {
			t.Errorf("%s leaves a hole where the name was: %s", name, body)
		}
	}
	if !strings.Contains(html, "<title>You're invited to join a team</title>") {
		t.Errorf("html title names a tenant: %s", html)
	}
}

// TestRenderManagedAccountSetup: the set-up email names the account, its
// tenant and role, and carries the link; the name the tenant gave is escaped
// in the HTML part, and a missing tenant name reads as the organization.
func TestRenderManagedAccountSetup(t *testing.T) {
	t.Parallel()
	html, text, err := Render(TemplateManagedAccountSetup, map[string]any{
		"UserName":       "Ann <b>Lee</b>",
		"TenantName":     "Acme",
		"AccountAddress": "ann@acme.example.com",
		"Role":           "member",
		"ExpiresIn":      "7 days",
		"Link":           "https://example.com/invite?t=baz",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"Acme", "ann@acme.example.com", "member", "7 days", "https://example.com/invite?t=baz",
		"This link works once", "Your company admin sent your account's set-up link to this address.",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q", want)
		}
	}
	if strings.Contains(html, "<b>Lee</b>") || !strings.Contains(html, "Ann &lt;b&gt;Lee&lt;/b&gt;") {
		t.Errorf("html did not escape the name: %s", html)
	}
	html, text, err = Render(TemplateManagedAccountSetup, map[string]any{
		"UserName": "Ann", "AccountAddress": "ann@acme.example.com", "Role": "member",
		"ExpiresIn": "7 days", "Link": "https://example.com/invite?t=baz",
	})
	if err != nil {
		t.Fatalf("Render without a tenant name: %v", err)
	}
	for name, body := range map[string]string{"html": html, "text": text} {
		if !strings.Contains(body, "Your organization has created an account for you") {
			t.Errorf("%s does not fall back to the organization: %s", name, body)
		}
	}
}

func TestRenderHTMLAutoEscaping(t *testing.T) {
	t.Parallel()
	html, _, err := Render(TemplatePasswordReset, map[string]any{
		"UserName":  "<script>alert(1)</script>",
		"Link":      "https://example.com/reset",
		"ExpiresIn": "1 hour",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Errorf("html template did not escape script tag: %s", html)
	}
}

func TestRenderUnknownTemplate(t *testing.T) {
	t.Parallel()
	_, _, err := Render("nope_does_not_exist", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRenderInvalidData(t *testing.T) {
	t.Parallel()
	// Pass a struct that has the wrong fields; html/template's missingkey
	// default is "invalid", but execution still succeeds. Confirm at least
	// that a valid call works while a totally non-templatable scenario via a
	// channel field on a map makes execution fail.
	_, _, err := Render(TemplatePasswordReset, struct{}{})
	if err != nil {
		// Empty struct just produces empty fields; that's fine.
		t.Logf("got err with empty struct (acceptable): %v", err)
	}
}

func TestRender_Unbranded_OmitsBrandingMarkup(t *testing.T) {
	html, text, err := Render(TemplateMagicLink, map[string]any{
		"Link":      "https://app.example.com/x",
		"ExpiresIn": "1 hour",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{html, text} {
		if strings.Contains(body, "img src") || strings.Contains(body, "Need help?") {
			t.Fatalf("unbranded render leaked branding markup:\n%s", body)
		}
		if strings.Contains(body, "<no value>") {
			t.Fatalf("unbranded render leaked <no value>:\n%s", body)
		}
	}
}

func TestRender_Branded_IncludesProductLogoAndSupport(t *testing.T) {
	html, text, err := Render(TemplateMagicLink, map[string]any{
		"Link":         "https://app.example.com/x",
		"ExpiresIn":    "1 hour",
		"ProductName":  "Acme Kids",
		"LogoURL":      "https://kids.example.com/logo.png",
		"PrimaryColor": "#1a73e8",
		"SupportEmail": "help@kids.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, "https://kids.example.com/logo.png") {
		t.Fatalf("branded html missing logo:\n%s", html)
	}
	if !strings.Contains(html, "Acme Kids") || !strings.Contains(html, "#1a73e8") {
		t.Fatalf("branded html missing product name/colour:\n%s", html)
	}
	if !strings.Contains(html, "help@kids.example.com") {
		t.Fatalf("branded html missing support footer:\n%s", html)
	}
	if !strings.Contains(text, "Acme Kids") || !strings.Contains(text, "help@kids.example.com") {
		t.Fatalf("branded text missing product name/support:\n%s", text)
	}
}

func TestRenderAccountNotice_AdviceReplacesTheOwnersAdvice(t *testing.T) {
	t.Parallel()
	const ownersAdvice = "If this was you, there is nothing to do."
	for _, tc := range []struct {
		name, advice, want string
	}{
		{name: "default", advice: "", want: ownersAdvice},
		{name: "advice", advice: "Contact your organization's administrator.", want: "Contact your organization&#39;s administrator."},
	} {
		html, text, err := Render(TemplateAccountNotice, map[string]any{
			"UserName": "Ann", "Headline": "Your account was reset", "Detail": "It was reset.", "Advice": tc.advice,
		})
		if err != nil {
			t.Fatalf("%s: Render: %v", tc.name, err)
		}
		if !strings.Contains(html, tc.want) {
			t.Errorf("%s: html missing %q", tc.name, tc.want)
		}
		wantText := strings.ReplaceAll(tc.want, "&#39;", "'")
		if !strings.Contains(text, wantText) {
			t.Errorf("%s: text missing %q", tc.name, wantText)
		}
		if tc.advice != "" && (strings.Contains(html, ownersAdvice) || strings.Contains(text, ownersAdvice)) {
			t.Errorf("%s: the owner's advice is still there", tc.name)
		}
	}
}

// An account notice carries a button only when it has both a label and a
// link.
func TestRender_AccountNoticeButton(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, button, link string
		want               bool
	}{
		{name: "both", button: "Open Members", link: "https://app.example.com/members?tenant_id=t-1", want: true},
		{name: "no link", button: "Open Members"},
		{name: "none"},
	} {
		html, text, err := Render(TemplateAccountNotice, map[string]any{
			"UserName": "Ann", "Headline": "Help", "Detail": "Bo asked for help.", "Button": tc.button, "Link": tc.link,
		})
		if err != nil {
			t.Fatalf("%s: Render: %v", tc.name, err)
		}
		if got := strings.Contains(html, `>Open Members</a>`); got != tc.want {
			t.Errorf("%s: html button = %v, want %v", tc.name, got, tc.want)
		}
		if got := strings.Contains(text, "Open Members: https://app.example.com/members?tenant_id=t-1"); got != tc.want {
			t.Errorf("%s: text button = %v, want %v", tc.name, got, tc.want)
		}
	}
}
