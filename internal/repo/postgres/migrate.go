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
