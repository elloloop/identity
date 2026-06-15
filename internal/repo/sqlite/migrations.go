package sqlite

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// runMigrations applies pending schema migrations to the open SQLite pool.
// It drives golang-migrate against the existing *sql.DB (via WithInstance)
// rather than a DSN so it works identically for on-disk and in-memory
// databases — the latter would otherwise open a second, independent
// connection and migrate the wrong (empty) database.
//
// Idempotent: applying to a fully-migrated database is a no-op
// (migrate.ErrNoChange is swallowed).
func runMigrations(pool *sql.DB) error {
	src, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("sqlite: open migrations source: %w", err)
	}
	driver, err := sqlitemigrate.WithInstance(pool, &sqlitemigrate.Config{})
	if err != nil {
		return fmt.Errorf("sqlite: init migrate driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "sqlite", driver)
	if err != nil {
		return fmt.Errorf("sqlite: init migrate: %w", err)
	}
	// Do NOT call m.Close(): it would close the shared *sql.DB pool out from
	// under the repository. The source instance has no OS resources to release
	// beyond the embedded FS.
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("sqlite: migrate up: %w", err)
	}
	return nil
}
