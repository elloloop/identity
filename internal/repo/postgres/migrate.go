package postgres

import (
	"errors"
	"strings"
)

// Migrate applies all pending schema migrations to the Postgres database
// at dsn, then returns. It is idempotent — a fully-migrated database is a
// no-op — and safe to run concurrently with other instances: the
// underlying runner holds a Postgres advisory lock for the duration, so
// exactly one caller applies the migrations and the rest wait, then
// no-op. It is the entry point behind the `identity migrate` deploy step
// (the explicit alternative to GATEWAY_POSTGRES_AUTO_MIGRATE).
func Migrate(dsn string) error {
	if strings.TrimSpace(dsn) == "" {
		return errors.New("postgres: Migrate: empty DSN")
	}
	return runMigrations(dsn)
}

// ForceMigrationVersion records version as the database's schema migration
// version and clears the dirty flag a failed migration leaves, without running
// any migration. It is the entry point behind `identity migrate force
// <version>`: after a failed migration, every later Migrate refuses to run
// until an operator has confirmed which version the schema is really at.
// version must be one of the embedded migrations. It returns the state it
// replaced, so the operator's record shows what was overwritten.
func ForceMigrationVersion(dsn string, version int) (MigrationState, error) {
	if strings.TrimSpace(dsn) == "" {
		return MigrationState{}, errors.New("postgres: ForceMigrationVersion: empty DSN")
	}
	return forceMigrationVersion(dsn, version)
}
