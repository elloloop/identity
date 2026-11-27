//go:build integration && realpostgres

package integration

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

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

// TestRedesign_ManagedHelp_SameAnswerForEveryAddress: the reply to a help
// request is the same for a managed account, a personal account and an
// address with no account, so it says nothing about who has one.
func TestRedesign_ManagedHelp_SameAnswerForEveryAddress(t *testing.T) {
	h := startManagedHarness(t, func(*config.Config) {})
	m := newManagedMember(t, h, "managed-help-same")
	client := brandedClient(h, "")
	var answers []*identitypb.RequestAdminHelpResponse
	var headers []string
	for _, addr := range []string{m.address, ownerAddress(t, h, m.ownerID), "nobody-" + m.mt.domain + "@example.org"} {
		resp, err := client.RequestAdminHelp(context.Background(), connect.NewRequest(&identitypb.RequestAdminHelpRequest{Email: addr, Reason: "locked out"}))
		if err != nil {
			t.Fatalf("RequestAdminHelp(%s): %v", addr, err)
		}
		answers = append(answers, resp.Msg)
		var keys []string
		for k := range resp.Header() {
			if k != "Date" {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		headers = append(headers, strings.Join(keys, ","))
	}
	for i := 1; i < len(answers); i++ {
		if !proto.Equal(answers[0], answers[i]) {
			t.Fatalf("answer %d = %v, want the same as %v", i, answers[i], answers[0])
		}
		if headers[i] != headers[0] {
			t.Fatalf("answer %d headers = %q, want %q", i, headers[i], headers[0])
		}
	}
}
