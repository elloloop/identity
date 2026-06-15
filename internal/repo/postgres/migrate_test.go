package postgres

import (
	"context"
	"os"
	"testing"
)

// TestMigrate_EmptyDSN_Errors runs without a database: an empty DSN must
// be rejected before any connection is attempted.
func TestMigrate_EmptyDSN_Errors(t *testing.T) {
	if err := Migrate(""); err == nil {
		t.Fatal(`Migrate(""): want error, got nil`)
	}
	if err := Migrate("   "); err == nil {
		t.Fatal(`Migrate("   "): want error for blank DSN, got nil`)
	}
}

// TestMigrate_AppliesAndIdempotent is the real-Postgres e2e: it applies
// the full migration set to the database at GATEWAY_TEST_POSTGRES_DSN,
// proves the second run is a no-op (idempotent), and that the resulting
// schema is usable. Skipped when the env var is unset (CI provides it).
func TestMigrate_AppliesAndIdempotent(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping real-postgres migrate e2e")
	}

	// First run applies every pending migration.
	if err := Migrate(dsn); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	// Second run is a no-op rather than an error (idempotent).
	if err := Migrate(dsn); err != nil {
		t.Fatalf("second Migrate (idempotent): %v", err)
	}

	// The migrated schema is usable: a read against a migrated table
	// succeeds and returns no rows on an empty database.
	ctx := context.Background()
	r, err := New(ctx, Config{DSN: dsn, MaxConns: 5, ProjectID: "migrate-test"})
	if err != nil {
		t.Fatalf("New after migrate: %v", err)
	}
	defer r.Close()
	if u, err := r.FindUserByEmail(ctx, "nobody@example.com"); err != nil {
		t.Fatalf("FindUserByEmail on migrated schema: %v", err)
	} else if u != nil {
		t.Fatalf("want nil user on empty schema, got %#v", u)
	}
}
