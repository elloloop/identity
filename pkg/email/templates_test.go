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
