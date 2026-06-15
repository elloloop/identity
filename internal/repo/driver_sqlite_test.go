package repo

import (
	"context"
	"testing"

	pgrepo "github.com/elloloop/identity/internal/repo/postgres"
)

// TestBuildSQLiteDriver exercises the full sqlite Build path: open the
// in-memory database, seed the default project, and return a complete Built
// (Repository + DB, no control plane — sqlite is the single-project tier).
func TestBuildSQLiteDriver(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Driver:     DriverSQLite,
		SQLitePath: ":memory:",
		ProjectID:  "proj_test",
	}
	built, err := Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Build sqlite: %v", err)
	}
	if built == nil || built.Repository == nil || built.DB == nil {
		t.Fatalf("Build sqlite returned incomplete result: %#v", built)
	}
	// SQLite is the embedded single-project tier: no postgres control plane.
	if built.ProjectStore != nil {
		t.Errorf("Build sqlite: ProjectStore = %v, want nil", built.ProjectStore)
	}
	assertNoGovernancePlane(t, built, "sqlite")
}

// TestBuildSQLiteRejectsInvalidConfig covers the two sqlite guard branches in
// Build: a missing path and a missing project ID both fail before any open.
func TestBuildSQLiteRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
	}{
		{"sqlite_missing_path", Config{Driver: DriverSQLite, ProjectID: "proj_test"}},
		{"sqlite_missing_project", Config{Driver: DriverSQLite, SQLitePath: ":memory:"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if built, err := Build(context.Background(), tt.cfg, nil); err == nil || built != nil {
				t.Fatalf("Build(%#v) = %#v, %v; want nil, error", tt.cfg, built, err)
			}
		})
	}
}

// TestPlatformAdminStoreIface pins both branches of the accessor: a nil store
// surfaces as a true nil interface, a present store threads through unchanged.
func TestPlatformAdminStoreIface(t *testing.T) {
	t.Parallel()

	if pa := (&Built{}).PlatformAdminStoreIface(); pa != nil {
		t.Errorf("empty PlatformAdminStoreIface() = %v, want true nil", pa)
	}
	full := &Built{PlatformAdminStore: &pgrepo.PlatformAdminStore{}}
	if full.PlatformAdminStoreIface() == nil {
		t.Error("full PlatformAdminStoreIface() = nil, want non-nil")
	}
}
