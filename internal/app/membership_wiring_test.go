package app

import (
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
)

// Interface-embedding stubs: they satisfy the store interfaces so
// buildMembershipService's non-nil check passes. Their methods are never
// called (the selector only stores them), so the embedded nil interface is
// fine.
type (
	stubInvitationStore struct{ service.InvitationStore }
	stubMembershipStore struct{ service.MembershipStore }
	stubTenantStore     struct{ service.TenantStore }
	stubUserDirectory   struct{ service.UserDirectory }
)

func TestBuildMembershipService(t *testing.T) {
	logger := zap.NewNop()
	users := &stubUserDirectory{}
	mailer := email.NewLogOnly(logger)

	full := Deps{
		Config:          &config.Config{},
		InvitationStore: &stubInvitationStore{},
		MembershipStore: &stubMembershipStore{},
		TenantStore:     &stubTenantStore{},
	}
	if got := buildMembershipService(full, users, mailer, logger); got == nil {
		t.Fatal("all stores present: want non-nil MembershipService, got nil")
	}

	// Missing any one store ⇒ nil (the memory driver has no governance plane).
	for name, mutate := range map[string]func(*Deps){
		"no invitation store": func(d *Deps) { d.InvitationStore = nil },
		"no membership store": func(d *Deps) { d.MembershipStore = nil },
		"no tenant store":     func(d *Deps) { d.TenantStore = nil },
	} {
		d := full
		mutate(&d)
		if got := buildMembershipService(d, users, mailer, logger); got != nil {
			t.Errorf("%s: want nil MembershipService, got non-nil", name)
		}
	}
}

func TestMailDeliveryConfigured(t *testing.T) {
	cases := []struct {
		name string
		deps Deps
		want bool
	}{
		{"injected transport", Deps{EmailTransport: email.NewLogOnly(zap.NewNop())}, true},
		{"nil config, no transport", Deps{}, false},
		{"smtp host set", Deps{Config: &config.Config{SMTPHost: "smtp.example.com"}}, true},
		{"smtp providers set", Deps{Config: &config.Config{SMTPProviders: `[{"host":"x"}]`}}, true},
		{"nothing configured", Deps{Config: &config.Config{}}, false},
	}
	for _, tc := range cases {
		if got := mailDeliveryConfigured(tc.deps); got != tc.want {
			t.Errorf("%s: mailDeliveryConfigured = %v, want %v", tc.name, got, tc.want)
		}
	}
}
