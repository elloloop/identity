//go:build integration && realpostgres

package integration

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
)

func requestAdminHelp(t *testing.T, h *RedesignHarness, addr string) {
	t.Helper()
	if _, err := brandedClient(h, "").RequestAdminHelp(context.Background(), connect.NewRequest(&identitypb.RequestAdminHelpRequest{
		Email: addr, Reason: "please call me on 555-0100",
	})); err != nil {
		t.Fatalf("RequestAdminHelp(%s): %v", addr, err)
	}
}

// TestRedesign_ManagedHelp_GoesToTheTenant: a help request about a managed
// account mails the tenant's owner and admin, once a day, with nothing the caller
// wrote; a request about a personal account mails no tenant.
func TestRedesign_ManagedHelp_GoesToTheTenant(t *testing.T) {
	h := startManagedHarness(t, func(c *config.Config) { c.TenantMembersPageURL = "https://app.example.com/members" })
	m := newManagedMember(t, h, "managed-help")
	owner, admin := ownerAddress(t, h, m.ownerID), ownerAddress(t, h, m.mt.admin.userID)

	h.Mailer.Reset()
	requestAdminHelp(t, h, strings.ToUpper(m.address))
	sent := h.Mailer.Sent()
	var to []string
	for _, msg := range sent {
		to = append(to, msg.To)
		if !strings.Contains(msg.Text, "Ann ("+m.address+") asked for help signing in.") || strings.Contains(msg.Text, "555-0100") {
			t.Fatalf("notice = %q, want the account's stored name and address and nothing the caller wrote", msg.Text)
		}
		if link := "Open Members: https://app.example.com/members?tenant_id=" + m.tenantID; !strings.Contains(msg.Text, link) {
			t.Fatalf("notice = %q, want %q", msg.Text, link)
		}
	}
	if len(to) != 2 || !slices.Contains(to, owner) || !slices.Contains(to, admin) {
		t.Fatalf("mail went to %v, want the tenant's owner and admin", to)
	}

	h.Mailer.Reset()
	requestAdminHelp(t, h, m.address)
	requestAdminHelp(t, h, owner)
	if sent := h.Mailer.Sent(); len(sent) != 0 {
		t.Fatalf("a repeat request and a personal account's request mailed %+v, want nothing", sent)
	}
}

// TestRedesign_ManagedHelp_OffTellsNoTenant: with managed accounts off, a
// request about a managed account is filed as any other and mails no one.
func TestRedesign_ManagedHelp_OffTellsNoTenant(t *testing.T) {
	h := startManagedHarness(t, func(*config.Config) {})
	m := newManagedMember(t, h, "managed-help-off")
	off := bootRedesignHarnessOn(t, h.ProjectID, h.TenantID, h.BrandedAuthDomain, func(*config.Config) {}, NewRecordingMailer())

	requestAdminHelp(t, off, m.address)
	if sent := off.Mailer.Sent(); len(sent) != 0 {
		t.Fatalf("with managed accounts off the request mailed %+v", sent)
	}
}
