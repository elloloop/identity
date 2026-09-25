package postgres

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"slices"
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
// later run refuses to start until an operator records which version the
// schema is at; the error then wraps a *DirtyMigrationError saying which.
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

// withDirtyVersionHint wraps err with a *DirtyMigrationError when the run
// left, or found, the schema version dirty.
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
	dirtyErr, derr := describeDirtyVersion(src, version)
	if derr != nil {
		return err
	}
	return fmt.Errorf("%w: %w", err, dirtyErr)
}

// describeDirtyVersion places a dirty version among the embedded migrations.
func describeDirtyVersion(src source.Driver, version uint) (*DirtyMigrationError, error) {
	versions, err := embeddedVersions(src)
	if err != nil {
		return nil, err
	}
	e := &DirtyMigrationError{Version: int(version), Latest: int(versions[len(versions)-1])}
	i := slices.Index(versions, version)
	if i < 0 {
		return e, nil
	}
	e.Known = true
	e.First = i == 0
	if i > 0 {
		e.Previous = int(versions[i-1])
	}
	if i+1 < len(versions) {
		e.Next = int(versions[i+1])
	}
	return e, nil
}

// embeddedVersions lists the versions of the embedded migrations, ascending.
func embeddedVersions(src source.Driver) ([]uint, error) {
	v, err := src.First()
	if err != nil {
		return nil, fmt.Errorf("postgres: list migrations: %w", err)
	}
	versions := []uint{v}
	for {
		v, err = src.Next(v)
		if errors.Is(err, fs.ErrNotExist) {
			return versions, nil
		}
		if err != nil {
			return nil, fmt.Errorf("postgres: list migrations: %w", err)
		}
		versions = append(versions, v)
	}
}

// DirtyMigrationError reports a schema version golang-migrate left marked
// dirty, placed among the migrations this build embeds, so a caller can name
// the version to record. golang-migrate marks the version a migration moves
// TO dirty before running it: going up that is the failed migration's own
// version, going down (rolling Next back) the version below it. Each embedded
// migration runs as one transaction, so a failed one leaves the schema where
// it was.
type DirtyMigrationError struct {
	// Version is the dirty version.
	Version int
	// Known reports whether this build embeds a migration with Version. When
	// it does not, a newer release migrated the database, and only that
	// release knows how to recover it.
	Known bool
	// Latest is the newest migration this build embeds.
	Latest int
	// First reports whether Version is the first embedded migration, so a
	// failed apply of it left no identity schema at all.
	First bool
	// Previous and Next are the embedded migrations around a known Version,
	// or 0 when there is none.
	Previous int
	Next     int
}

func (e *DirtyMigrationError) Error() string {
	if !e.Known {
		return fmt.Sprintf("schema version %d is marked dirty, and it is not a migration this build embeds "+
			"(the latest is %d): a newer identity release migrated this database. Recover it with that release; "+
			"do not record an older version or clear the migration history from this build", e.Version, e.Latest)
	}
	msg := fmt.Sprintf("schema version %d is marked dirty because a migration failed part-way; "+
		"each migration runs in one transaction, so the failed one left no change behind. ", e.Version)
	if e.First {
		msg += fmt.Sprintf("If applying migration %d, the first, failed, the database holds no identity schema "+
			"and its migration history can be cleared", e.Version)
	} else {
		msg += fmt.Sprintf("If applying migration %d failed, record version %d", e.Version, e.Previous)
	}
	if e.Next > 0 {
		msg += fmt.Sprintf("; if rolling back migration %d failed, record version %d", e.Next, e.Next)
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
	versions, err := embeddedVersions(src)
	if err != nil {
		return err
	}
	if !slices.Contains(versions, uint(version)) {
		return fmt.Errorf("postgres: no migration has version %d", version)
	}
	return nil
}

// pgx5 driver registration sentinel — keeps the import alive even
// though we only use the side-effect.
var _ = pgx.Postgres{}
