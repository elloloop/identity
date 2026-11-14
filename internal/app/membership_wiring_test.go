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
	if got := buildMembershipService(full, nil, users, mailer, false, nil, logger); got == nil {
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
		if got := buildMembershipService(d, nil, users, mailer, false, nil, logger); got != nil {
			t.Errorf("%s: want nil MembershipService, got non-nil", name)
		}
	}
}
