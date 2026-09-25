package postgres

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationsDir is the directory inside migrationFS holding the .sql files.
const migrationsDir = "migrations"

// runMigrations applies any pending schema migrations to the target
// Postgres database. It is idempotent: calling it on a fully-migrated
// database is a no-op (migrate.ErrNoChange is swallowed).
//
// The migrations are read from the embedded migrationFS so the binary
// is self-contained — operators do not need to ship the .sql files
// separately.
//
// A migration that fails leaves the schema version marked dirty, and every
// later run refuses to start until an operator says which version the schema
// is at; the error then names the command that does (see dirtyVersionError).
func runMigrations(dsn string) error {
	m, err := newMigrator(dsn)
	if err != nil {
		return err
	}
	defer closeMigrator(m)
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("postgres: migrate up: %w", withDirtyVersionHint(m, err))
	}
	return nil
}

// forceMigrationVersion records version as the schema's migration version
// and clears the dirty flag, without running any migration, and returns the
// state it replaced. version must be one of the embedded migrations.
func forceMigrationVersion(dsn string, version int) (MigrationState, error) {
	src, err := iofs.New(migrationFS, migrationsDir)
	if err != nil {
		return MigrationState{}, fmt.Errorf("postgres: open migrations source: %w", err)
	}
	err = requireKnownVersion(src, version)
	_ = src.Close()
	if err != nil {
		return MigrationState{}, err
	}
	m, err := newMigrator(dsn)
	if err != nil {
		return MigrationState{}, err
	}
	defer closeMigrator(m)
	var replaced MigrationState
	switch v, dirty, verr := m.Version(); {
	case errors.Is(verr, migrate.ErrNilVersion):
	case verr != nil:
		return MigrationState{}, fmt.Errorf("postgres: read migration version: %w", verr)
	default:
		replaced = MigrationState{Version: int(v), Dirty: dirty}
	}
	if err := m.Force(version); err != nil {
		return MigrationState{}, fmt.Errorf("postgres: force migration version %d: %w", version, err)
	}
	return replaced, nil
}

// MigrationState is a database's recorded schema migration version. Version
// is 0 when no migration has been recorded.
type MigrationState struct {
	Version int
	Dirty   bool
}

// withDirtyVersionHint adds the recovery to err when the run left, or found,
// the schema version dirty.
func withDirtyVersionHint(m *migrate.Migrate, err error) error {
	version, dirty, verr := m.Version()
	if verr != nil || !dirty {
		return err
	}
	src, serr := iofs.New(migrationFS, migrationsDir)
	if serr != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	hint := dirtyVersionError{version: int(version)}
	if prev, perr := src.Prev(version); perr == nil {
		hint.previous = int(prev)
	}
	if next, nerr := src.Next(version); nerr == nil {
		hint.next = int(next)
	}
	return fmt.Errorf("%w: %w", err, hint)
}

// dirtyVersionError explains a dirty schema version and names the command
// that clears it. golang-migrate marks the version a migration moves TO dirty
// before running it: going up that is the failed migration's own version,
// going down (rolling migration next back) the version below it. Each identity
// migration runs as one transaction, so a failed one leaves the schema where
// it was, and the operator records that version.
type dirtyVersionError struct {
	version  int
	previous int // the migration before version; 0 when version is the first
	next     int // the migration after version; 0 when version is the last
}

func (e dirtyVersionError) Error() string {
	msg := fmt.Sprintf("schema version %d is marked dirty because a migration failed part-way. "+
		"Each identity migration runs in one transaction, so the failed one left no change behind. ", e.version)
	if e.previous > 0 {
		msg += fmt.Sprintf("If applying migration %d failed, confirm its changes are absent, then run "+
			"`identity migrate force %d` followed by `identity migrate`", e.version, e.previous)
	} else {
		msg += fmt.Sprintf("If applying migration %d, the first, failed, the database holds no identity schema: "+
			"drop the schema_migrations table and run `identity migrate` again", e.version)
	}
	if e.next > 0 {
		msg += fmt.Sprintf(". If rolling back migration %d failed, run `identity migrate force %d`", e.next, e.next)
	}
	return msg
}

func newMigrator(dsn string) (*migrate.Migrate, error) {
	src, err := iofs.New(migrationFS, migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("postgres: open migrations source: %w", err)
	}
	// migrate.NewWithSourceInstance only accepts a database URL form, and
	// dispatches by its scheme: rewrite postgres:// and postgresql:// to the
	// pgx5:// scheme the pgx/v5 driver (imported above) registers.
	migrateDSN := dsn
	for _, scheme := range []string{"postgres://", "postgresql://"} {
		if strings.HasPrefix(migrateDSN, scheme) {
			migrateDSN = "pgx5://" + strings.TrimPrefix(migrateDSN, scheme)
			break
		}
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, migrateDSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: init migrate: %w", err)
	}
	return m, nil
}

// closeMigrator releases m. Its errors are ignored: the underlying DB pool is
// closed elsewhere and there is no useful recovery action.
func closeMigrator(m *migrate.Migrate) {
	_, _ = m.Close()
}

// requireKnownVersion refuses a version no embedded migration has, so a typo
// cannot record a schema version that does not exist.
func requireKnownVersion(src source.Driver, version int) error {
	if version < 1 {
		return fmt.Errorf("postgres: migration version must be positive, got %d", version)
	}
	v, err := src.First()
	for err == nil {
		if int(v) == version {
			return nil
		}
		v, err = src.Next(v)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("postgres: no migration has version %d", version)
	}
	return fmt.Errorf("postgres: list migrations: %w", err)
}

// pgx5 driver registration sentinel — keeps the import alive even
// though we only use the side-effect.
var _ = pgx.Postgres{}
