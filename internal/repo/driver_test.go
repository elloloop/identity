package repo

import (
	"context"
	"math"
	"strings"
	"testing"

	pgrepo "github.com/elloloop/identity/internal/repo/postgres"
	"go.uber.org/zap"
)

func TestBuildMemoryDriver(t *testing.T) {
	t.Parallel()

	built, err := Build(context.Background(), Config{Driver: DriverMemory}, nil)
	if err != nil {
		t.Fatalf("Build memory: %v", err)
	}
	if built == nil || built.Repository == nil || built.DB == nil {
		t.Fatalf("Build memory returned incomplete result: %#v", built)
	}
	// The control plane is postgres-only; memory has none.
	if built.ProjectStore != nil {
		t.Errorf("Build memory: ProjectStore = %v, want nil", built.ProjectStore)
	}
	assertNoGovernancePlane(t, built, "memory")
}

// assertNoGovernancePlane verifies a control-plane-free driver's accessors
// return true nils (not interfaces wrapping typed-nil pointers) so the
// service layer's `== nil` checks behave. Covers ProjectResolver,
// TenantAutoFormer and LoginGovernance together.
func assertNoGovernancePlane(t *testing.T, built *Built, driver string) {
	t.Helper()
	if r := built.ProjectResolver(); r != nil {
		t.Errorf("Build %s: ProjectResolver() = %v, want true nil", driver, r)
	}
	if af := built.TenantAutoFormer(); af != nil {
		t.Errorf("Build %s: TenantAutoFormer() = %v, want true nil", driver, af)
	}
	if cp := built.ControlPlaneStore(); cp != nil {
		t.Errorf("Build %s: ControlPlaneStore() = %v, want true nil", driver, cp)
	}
	if g := built.LoginGovernance(); g != nil {
		t.Errorf("Build %s: LoginGovernance() = %v, want true nil", driver, g)
	}
}

func TestBuildMemoryDriver_AcceptsExplicitLogger(t *testing.T) {
	t.Parallel()

	built, err := Build(context.Background(), Config{Driver: DriverMemory}, zap.NewNop())
	if err != nil || built == nil {
		t.Fatalf("Build memory with logger: built=%v err=%v", built, err)
	}
}

func TestBuildRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
	}{
		{"unknown_driver", Config{Driver: Driver("unknown")}},
		{"postgres_missing_dsn", Config{Driver: DriverPostgres, ProjectID: "tenant"}},
		{"postgres_missing_project", Config{Driver: DriverPostgres, PostgresDSN: "postgres://example"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if built, err := Build(context.Background(), tt.cfg, nil); err == nil || built != nil {
				t.Fatalf("Build(%#v) = %#v, %v; want nil, error", tt.cfg, built, err)
			}
		})
	}
}

func TestBuild_PostgresMaxConnsExceedsInt32(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Driver:           DriverPostgres,
		PostgresDSN:      "postgres://example",
		ProjectID:        "tenant",
		PostgresMaxConns: math.MaxInt32 + 1,
	}
	_, err := Build(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds int32") {
		t.Fatalf("Build with oversized max connections: err = %v, want int32 overflow", err)
	}
}

// TestBuilt_GovernanceAccessors_TypedNilAvoidance pins the contract every
// driver-agnostic accessor exists for: a nil concrete store must surface as a
// TRUE nil interface (not a typed nil wrapping a nil pointer), and a present
// store must surface unchanged. The empty Built models the memory shape
// (no control plane); the populated Built models the postgres shape.
func TestBuilt_GovernanceAccessors_TypedNilAvoidance(t *testing.T) {
	t.Parallel()

	// Empty build: every accessor is a true nil interface.
	empty := &Built{}
	if empty.ProjectResolver() != nil {
		t.Error("empty ProjectResolver: want nil interface")
	}
	if empty.ControlPlaneStore() != nil {
		t.Error("empty ControlPlaneStore: want nil interface")
	}
	if empty.TenantAutoFormer() != nil {
		t.Error("empty TenantAutoFormer: want nil interface")
	}
	if empty.DomainStoreIface() != nil {
		t.Error("empty DomainStoreIface: want nil interface")
	}
	if empty.TenantStoreIface() != nil {
		t.Error("empty TenantStoreIface: want nil interface")
	}
	if empty.MembershipStoreIface() != nil {
		t.Error("empty MembershipStoreIface: want nil interface")
	}
	if empty.InvitationStoreIface() != nil {
		t.Error("empty InvitationStoreIface: want nil interface")
	}
	if empty.LoginGovernance() != nil {
		t.Error("empty LoginGovernance: want nil")
	}

	// Populated build (postgres shape): each accessor returns its store. The
	// zero-value store pointers are non-nil; the accessors only thread them
	// through, so no pool/connection is touched.
	full := &Built{
		ProjectStore:     &pgrepo.ProjectStore{},
		AutoFormStore:    &pgrepo.AutoFormStore{},
		DomainStore:      &pgrepo.DomainStore{},
		TenantStore:      &pgrepo.TenantStore{},
		MembershipStore:  &pgrepo.MembershipStore{},
		LoginPolicyStore: &pgrepo.LoginPolicyStore{},
		InvitationStore:  &pgrepo.InvitationStore{},
	}
	if full.ProjectResolver() == nil {
		t.Error("full ProjectResolver: want non-nil")
	}
	if full.ControlPlaneStore() == nil {
		t.Error("full ControlPlaneStore: want non-nil")
	}
	if full.TenantAutoFormer() == nil {
		t.Error("full TenantAutoFormer: want non-nil")
	}
	if full.DomainStoreIface() == nil {
		t.Error("full DomainStoreIface: want non-nil")
	}
	if full.TenantStoreIface() == nil {
		t.Error("full TenantStoreIface: want non-nil")
	}
	if full.MembershipStoreIface() == nil {
		t.Error("full MembershipStoreIface: want non-nil")
	}
	if full.InvitationStoreIface() == nil {
		t.Error("full InvitationStoreIface: want non-nil")
	}
	if full.LoginGovernance() == nil {
		t.Error("full LoginGovernance: want non-nil")
	}
}
