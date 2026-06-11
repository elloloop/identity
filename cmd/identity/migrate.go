package main

import (
	"go.uber.org/zap"

	"github.com/elloloop/identity/identityserver"
)

// migrateRequested reports whether argv selects the `migrate` subcommand
// (`identity migrate`), as opposed to the default serve behaviour.
func migrateRequested(args []string) bool {
	return len(args) > 1 && args[1] == "migrate"
}

// runMigrate applies pending Postgres schema migrations and returns a
// process exit code (0 = success, 1 = failure). It runs migrations and
// returns without starting the server — the deploy-step path used by, e.g.,
// a Kubernetes Job gated ahead of a rollout. See
// docs-site Installation → Database & Migrations.
func runMigrate(opts identityserver.Options, logger *zap.Logger) int {
	logger.Info("identity_migrate_starting")
	if err := identityserver.Migrate(opts); err != nil {
		logger.Error("identity_migrate_failed", zap.Error(err))
		return 1
	}
	logger.Info("identity_migrate_complete")
	return 0
}
