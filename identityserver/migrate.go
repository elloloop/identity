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
