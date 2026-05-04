package postgres

import (
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// runMigrations applies any pending schema migrations to the target
// Postgres database. It is idempotent: calling it on a fully-migrated
// database is a no-op (migrate.ErrNoChange is swallowed).
//
// The migrations are read from the embedded migrationFS so the binary
// is self-contained — operators do not need to ship the .sql files
// separately.
func runMigrations(dsn string) error {
	src, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("postgres: open migrations source: %w", err)
	}
	// Use the pgx/v5 migrate driver's "pgx5://" URL prefix so it picks
	// the matching driver. pgx5 understands the standard "postgres://"
	// DSN underneath, but the migrate library dispatches by the URL
	// scheme it sees.
	migrateDSN := dsn
	// migrate.NewWithSourceInstance only accepts a database URL form,
	// so we must rewrite the scheme to pgx5:// for the registered
	// driver (registered as a side-effect of the import above).
	if len(migrateDSN) >= len("postgres://") && migrateDSN[:len("postgres://")] == "postgres://" {
		migrateDSN = "pgx5://" + migrateDSN[len("postgres://"):]
	} else if len(migrateDSN) >= len("postgresql://") && migrateDSN[:len("postgresql://")] == "postgresql://" {
		migrateDSN = "pgx5://" + migrateDSN[len("postgresql://"):]
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, migrateDSN)
	if err != nil {
		return fmt.Errorf("postgres: init migrate: %w", err)
	}
	defer func() {
		// Errors here are logged-and-ignored: the underlying DB pool
		// is closed elsewhere and there is no useful recovery action.
		_, _ = m.Close()
	}()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("postgres: migrate up: %w", err)
	}
	return nil
}

// pgx5 driver registration sentinel — keeps the import alive even
// though we only use the side-effect.
var _ = pgx.Postgres{}
