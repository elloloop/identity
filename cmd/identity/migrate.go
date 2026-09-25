package main

import (
	"fmt"
	"strconv"

	"go.uber.org/zap"

	"github.com/elloloop/identity/identityserver"
)

// migrateRequested reports whether argv selects the `migrate` subcommand
// (`identity migrate`), as opposed to the default serve behaviour.
func migrateRequested(args []string) bool {
	return len(args) > 1 && args[1] == "migrate"
}

// unknownSubcommand reports whether argv carries a first positional argument
// that is not a recognised subcommand. The server takes no positional args, so
// an unrecognised one (e.g. a typo'd "migate") must fail fast rather than
// silently starting the long-running server — which would hang a one-shot
// migrate Job (restartPolicy: Never).
func unknownSubcommand(args []string) bool {
	return len(args) > 1 && args[1] != "migrate"
}

// migrateForceArg selects `identity migrate force <version>`.
const migrateForceArg = "force"

// migrateUsage is the migrate subcommand's synopsis, logged on a bad
// invocation.
const migrateUsage = "identity migrate [force <version>]"

// migrateCommand is a parsed `identity migrate` invocation.
type migrateCommand struct {
	// forceVersion, when positive, records that schema version and clears a
	// failed migration's dirty flag instead of running migrations.
	forceVersion int
}

// parseMigrateCommand parses the arguments after `identity migrate`: none,
// or `force` and exactly one positive version. Anything else is refused
// rather than ignored, so a mistyped invocation cannot run migrations the
// operator did not ask for.
func parseMigrateCommand(args []string) (migrateCommand, error) {
	if len(args) == 2 {
		return migrateCommand{}, nil
	}
	if args[2] != migrateForceArg || len(args) != 4 {
		return migrateCommand{}, fmt.Errorf("usage: %s", migrateUsage)
	}
	version, err := strconv.Atoi(args[3])
	if err != nil || version < 1 {
		return migrateCommand{}, fmt.Errorf("migrate force: version must be a positive integer, got %q", args[3])
	}
	return migrateCommand{forceVersion: version}, nil
}

// runMigrate applies pending Postgres schema migrations — or, for `migrate
// force <version>`, records that version and clears a failed migration's
// dirty flag — and returns a process exit code (0 = success, 1 = failure).
// It returns without starting the server: the deploy-step path used by, e.g.,
// a Kubernetes Job gated ahead of a rollout. See docs-site Installation →
// Database & Migrations.
func runMigrate(opts identityserver.Options, cmd migrateCommand, logger *zap.Logger) int {
	if cmd.forceVersion > 0 {
		logger.Info("identity_migrate_force_starting", zap.Int("version", cmd.forceVersion))
		previous, previousDirty, err := identityserver.ForceMigrationVersion(opts, cmd.forceVersion)
		if err != nil {
			logger.Error("identity_migrate_force_failed", zap.Error(err))
			return 1
		}
		logger.Info("identity_migrate_force_complete",
			zap.Int("version", cmd.forceVersion),
			zap.Int("previous_version", previous),
			zap.Bool("previous_dirty", previousDirty))
		return 0
	}
	logger.Info("identity_migrate_starting")
	if err := identityserver.Migrate(opts); err != nil {
		logger.Error("identity_migrate_failed", zap.Error(err))
		return 1
	}
	logger.Info("identity_migrate_complete")
	return 0
}
