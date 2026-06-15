package sqlite

import (
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config controls how the SQLite repository opens its database.
//
// Path is either a filesystem path (created if missing) or the literal
// ":memory:" for an ephemeral in-process database. MaxConns caps the
// connection pool for on-disk databases; in-memory databases are always
// pinned to a single connection (see New). ProjectID is the project
// (storage shard) this instance binds to — every data-plane row carries it
// and the mandatory `WHERE project_id = $1` predicate is bound here
// (ADR-0002).
type Config struct {
	Path      string
	MaxConns  int
	ProjectID string
}

// DefaultMaxConns is used when Config.MaxConns is zero. SQLite is a
// single-writer engine, so a small pool is plenty for the embedded tier.
const DefaultMaxConns = 4

// MemoryPath is the sentinel Path value selecting an in-memory database.
const MemoryPath = ":memory:"

// ConfigFromEnv reads Config from GATEWAY_SQLITE_* env vars. projectID is
// passed in (rather than read from env) because identity already plumbs
// cfg.DefaultProjectID through its own config.
func ConfigFromEnv(projectID string) Config {
	return Config{
		Path:      os.Getenv("GATEWAY_SQLITE_PATH"),
		MaxConns:  envInt("GATEWAY_SQLITE_MAX_CONNS", DefaultMaxConns),
		ProjectID: projectID,
	}
}

func (c *Config) applyDefaults() {
	if c.MaxConns <= 0 {
		c.MaxConns = DefaultMaxConns
	}
}

func (c *Config) validate() error {
	if c == nil {
		return errors.New("sqlite: nil config")
	}
	if strings.TrimSpace(c.Path) == "" {
		return errors.New("sqlite: Path is required (set GATEWAY_SQLITE_PATH, or \":memory:\")")
	}
	if strings.TrimSpace(c.ProjectID) == "" {
		return errors.New("sqlite: ProjectID is required")
	}
	return nil
}

// isMemory reports whether the configured path selects an in-memory database.
func (c *Config) isMemory() bool {
	return c.Path == MemoryPath || strings.HasPrefix(c.Path, "file::memory:")
}

// dsn builds the modernc.org/sqlite DSN and reports whether it is in-memory.
func (c *Config) dsn() (dsn string, inMemory bool) {
	inMemory = c.isMemory()
	base := c.Path
	if c.Path == MemoryPath {
		// A named shared-cache in-memory DB so the single pinned connection
		// (and any health-check ping) all address the same database.
		base = "file::memory:?cache=shared"
	}
	return withPragmas(base), inMemory
}

// withPragmas appends the connection pragmas every SQLite connection needs:
// foreign_keys(1) so the ON DELETE CASCADE chains fire (SQLite leaves FK
// enforcement OFF by default — it is a per-connection setting), and
// busy_timeout so a concurrent writer waits briefly instead of failing
// immediately with "database is locked". modernc applies each _pragma query
// parameter on every connection it opens. Centralised here so the file,
// in-memory, and test DSN paths all get identical enforcement.
func withPragmas(dsn string) string {
	const pragmas = "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + pragmas
}

// memoryDSNForName builds a uniquely-named shared in-memory DSN with the
// connection pragmas applied. Tests use it so each in-memory store is
// isolated from every other (a plain ":memory:" with cache=shared would
// otherwise be process-global).
func memoryDSNForName(name string) string {
	return withPragmas("file:" + url.PathEscape(name) + "?mode=memory&cache=shared")
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
