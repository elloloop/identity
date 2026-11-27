package email

import (
	"os"
	"strings"
	"testing"
)

// tenantInvitationCases are the invitation emails whose rendering is pinned
// byte for byte in testdata/, one branded and naming its tenant, one neither.
func tenantInvitationCases() map[string]map[string]any {
	return map[string]map[string]any{
		"tenant_invitation_branded": {
			"UserName": "jane", "InviterName": "A tenant administrator", "TenantName": "Acme Widgets",
			"Role": "member", "ExpiresIn": "7 days", "Link": "https://auth.example.com/auth/accept-invitation?token=abc",
			"ProductName": "Acme", "LogoURL": "https://example.com/logo.png", "PrimaryColor": "#123456", "SupportEmail": "support@example.com",
		},
		"tenant_invitation_unbranded": {
			"UserName": "jane", "InviterName": "A tenant administrator", "TenantName": "",
			"Role": "admin", "ExpiresIn": "7 days", "Link": "https://auth.example.com/auth/accept-invitation?token=abc",
			"ProductName": "", "LogoURL": "", "PrimaryColor": "", "SupportEmail": "",
		},
	}
}

// TestRenderTenantInvitation_Golden pins the invitation email exactly, in
// both parts, so a change to the template shows up as a change to the email.
// An invitation without a note renders as it did before notes existed,
// whether NoteLines is absent, nil or empty.
func TestRenderTenantInvitation_Golden(t *testing.T) {
	t.Parallel()
	for name, data := range tenantInvitationCases() {
		for variant, noteLines := range map[string]any{"absent": nil, "nil": []string(nil), "empty": []string{}} {
			t.Run(name+"/"+variant, func(t *testing.T) {
				t.Parallel()
				withNote := map[string]any{}
				for k, v := range data {
					withNote[k] = v
				}
				if variant != "absent" {
					withNote["NoteLines"] = noteLines
				}
				html, text, err := Render(TemplateTenantInvitation, withNote)
				if err != nil {
					t.Fatalf("Render: %v", err)
				}
				assertGolden(t, "testdata/"+name+".html", html)
				assertGolden(t, "testdata/"+name+".txt", text)
			})
		}
	}
}

// TestRenderTenantInvitation_NoteGolden pins an email carrying a two-line
// note: labelled as the inviting administrator's, after the invitation and
// before the link, quoted in the text part and set apart in the HTML part.
func TestRenderTenantInvitation_NoteGolden(t *testing.T) {
	t.Parallel()
	data := tenantInvitationCases()["tenant_invitation_branded"]
	data["NoteLines"] = []string{"Your mail address will be jane@example.com", "See you on Monday."}
	html, text, err := Render(TemplateTenantInvitation, data)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	assertGolden(t, "testdata/tenant_invitation_note.html", html)
	assertGolden(t, "testdata/tenant_invitation_note.txt", text)
}

// TestRenderTenantInvitation_NoteEscapedInHTML: the HTML part escapes the
// note, so text the service would refuse still renders as text, and the text
// part, which no client reads as markup, shows it as written.
func TestRenderTenantInvitation_NoteEscapedInHTML(t *testing.T) {
	t.Parallel()
	data := tenantInvitationCases()["tenant_invitation_unbranded"]
	data["NoteLines"] = []string{`<a href="https://example.test">x</a>`, `Tom & Jerry's "team"`}
	html, text, err := Render(TemplateTenantInvitation, data)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	const escaped = `&lt;a href=&#34;https://example.test&#34;&gt;x&lt;/a&gt;<br>Tom &amp; Jerry&#39;s &#34;team&#34;`
	if !strings.Contains(html, escaped) {
		t.Errorf("html does not carry the escaped note:\n%s", html)
	}
	if strings.Contains(html, `<a href="https://example.test"`) {
		t.Errorf("html carries the note as markup:\n%s", html)
	}
	if !strings.Contains(text, "> <a href=\"https://example.test\">x</a>\n> Tom & Jerry's \"team\"\n") {
		t.Errorf("text does not carry the note as written:\n%s", text)
	}
}

func assertGolden(t *testing.T, path, got string) {
	t.Helper()
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if got != string(want) {
		t.Errorf("%s differs:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}
