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
