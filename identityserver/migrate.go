package identityserver

import (
	"errors"
	"fmt"
	"strings"

	pgrepo "github.com/elloloop/identity/internal/repo/postgres"
)

// Migrate applies any pending Postgres schema migrations using opts.Config,
// then returns. It requires GATEWAY_POSTGRES_DSN (opts.Config.PostgresDSN)
// to be set.
//
// This is the programmatic entry point behind the `identity migrate`
// subcommand. Embedders can call it before New/Start to migrate the schema
// as an explicit deploy step rather than via GATEWAY_POSTGRES_AUTO_MIGRATE.
// It is idempotent and safe to run from multiple instances concurrently
// (the runner holds a Postgres advisory lock).
func Migrate(opts Options) error {
	dsn := strings.TrimSpace(opts.Config.PostgresDSN)
	if dsn == "" {
		return errors.New("identityserver: Migrate requires GATEWAY_POSTGRES_DSN to be set")
	}
	if err := pgrepo.Migrate(dsn); err != nil {
		return fmt.Errorf("identityserver: migrate: %w", err)
	}
	return nil
}

// ForceMigrationVersion records version as the Postgres schema's migration
// version and clears the dirty flag a failed migration leaves, without
// running any migration. It is the programmatic entry point behind
// `identity migrate force <version>`; Migrate's error names the version to
// force when it finds the schema dirty. It returns the version and dirty
// flag it replaced (version 0 when none was recorded). It requires
// GATEWAY_POSTGRES_DSN.
func ForceMigrationVersion(opts Options, version int) (previousVersion int, previousDirty bool, err error) {
	dsn := strings.TrimSpace(opts.Config.PostgresDSN)
	if dsn == "" {
		return 0, false, errors.New("identityserver: ForceMigrationVersion requires GATEWAY_POSTGRES_DSN to be set")
	}
	replaced, err := pgrepo.ForceMigrationVersion(dsn, version)
	if err != nil {
		return 0, false, fmt.Errorf("identityserver: force migration version: %w", err)
	}
	return replaced.Version, replaced.Dirty, nil
}

// DirtyMigrationError is the error Migrate wraps when the schema version is
// left, or found, dirty by a failed migration. It says where that version
// sits among the migrations this build ships, so the caller can decide which
// version to record with ForceMigrationVersion — or that a newer release must
// recover the database. Match it with errors.As.
type DirtyMigrationError = pgrepo.DirtyMigrationError
