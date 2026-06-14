package app

import (
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// stubControlPlaneStore satisfies service.ControlPlaneProjectStore so
// buildControlPlaneAdminService's non-nil check passes. Its methods are never
// called (the selector only stores it).
type stubControlPlaneStore struct {
	service.ControlPlaneProjectStore
}

func TestBuildControlPlaneAdminService(t *testing.T) {
	logger := zap.NewNop()

	full := Deps{
		Config:            &config.Config{AdminAPISecret: "operator-secret"},
		ControlPlaneStore: &stubControlPlaneStore{},
		TenantStore:       &stubTenantStore{},
		MembershipStore:   &stubMembershipStore{},
	}

	// All stores present AND a secret configured ⇒ non-nil and enabled.
	svc := buildControlPlaneAdminService(full, logger)
	if svc == nil {
		t.Fatal("all stores + secret: want non-nil ControlPlaneAdminService, got nil")
	}
	if !svc.Enabled() {
		t.Fatal("a configured secret must yield an enabled service")
	}

	// All stores present but NO secret ⇒ still constructed (so the handler is
	// wired) but DISABLED, so the surface returns Unimplemented.
	noSecret := full
	noSecret.Config = &config.Config{}
	svc = buildControlPlaneAdminService(noSecret, logger)
	if svc == nil {
		t.Fatal("stores present, empty secret: want a constructed-but-disabled service, got nil")
	}
	if svc.Enabled() {
		t.Fatal("an empty secret must yield a disabled service")
	}

	// A nil config is tolerated (empty secret ⇒ disabled).
	nilCfg := full
	nilCfg.Config = nil
	svc = buildControlPlaneAdminService(nilCfg, logger)
	if svc == nil {
		t.Fatal("nil config with stores present: want a disabled service, got nil")
	}
	if svc.Enabled() {
		t.Fatal("nil config implies no secret ⇒ disabled")
	}

	// Missing any one store ⇒ nil (entdb/memory have no control plane).
	for name, mutate := range map[string]func(*Deps){
		"no control-plane store": func(d *Deps) { d.ControlPlaneStore = nil },
		"no tenant store":        func(d *Deps) { d.TenantStore = nil },
		"no membership store":    func(d *Deps) { d.MembershipStore = nil },
	} {
		d := full
		mutate(&d)
		if got := buildControlPlaneAdminService(d, logger); got != nil {
			t.Errorf("%s: want nil ControlPlaneAdminService, got non-nil", name)
		}
	}
}
