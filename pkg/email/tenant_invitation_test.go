package email

import (
	"os"
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
func TestRenderTenantInvitation_Golden(t *testing.T) {
	t.Parallel()
	for name, data := range tenantInvitationCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			html, text, err := Render(TemplateTenantInvitation, data)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			assertGolden(t, "testdata/"+name+".html", html)
			assertGolden(t, "testdata/"+name+".txt", text)
		})
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
