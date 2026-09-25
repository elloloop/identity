package identityserver

import (
	"strings"
	"testing"
)

// TestMigrate_RequiresPostgresDSN runs without a database: Migrate must
// fail fast when no Postgres DSN is configured rather than attempting a
// nil connection.
func TestMigrate_RequiresPostgresDSN(t *testing.T) {
	err := Migrate(Options{}) // empty Config → no PostgresDSN
	if err == nil {
		t.Fatal("Migrate with no PostgresDSN: want error, got nil")
	}
	if !strings.Contains(err.Error(), "POSTGRES_DSN") {
		t.Fatalf("error should name the missing DSN env var, got: %v", err)
	}
}

// TestForceMigrationVersion_RequiresPostgresDSN: forcing a version needs a
// database as much as migrating does.
func TestForceMigrationVersion_RequiresPostgresDSN(t *testing.T) {
	_, _, err := ForceMigrationVersion(Options{}, 33, false)
	if err == nil || !strings.Contains(err.Error(), "POSTGRES_DSN") {
		t.Fatalf("ForceMigrationVersion with no PostgresDSN: err = %v, want one naming the DSN env var", err)
	}
}
