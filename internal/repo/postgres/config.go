package postgres

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config controls how the postgres repository connects to its database.
//
// DSN is the libpq-style connection string, e.g.
//
//	postgres://user:pass@host:5432/dbname?sslmode=disable
//
// MaxConns caps the underlying pgxpool. A zero value means "use the
// pgxpool default" (currently 4 + GOMAXPROCS-ish). 25 is the suggested
// default for an identity service node (see DefaultMaxConns).
//
// ConnTimeout is the per-acquire timeout used when checking a connection
// out of the pool. It does NOT bound the total query time — callers
// are still responsible for passing a context with the appropriate
// deadline.
//
// AutoMigrate controls whether New() applies pending schema migrations
// on first connect. In CI / dev / test we want true (the default); in
// strict production deploys teams may flip it to false and run
// `migrate ... up` from a deploy pipeline instead.
//
// ProjectID is the project (storage shard) whose rows this repository
// instance writes and reads. Per ADR-0002 the Project is identity's
// isolation shard: every data-plane row carries project_id and the
// mandatory `WHERE project_id = $1` predicate is bound here. Multi-project
// deployments derive a per-request scope via WithProject; the common
// zero-config single-project boot plumbs cfg.DefaultProjectID straight
// through.
type Config struct {
	DSN         string
	MaxConns    int32
	ConnTimeout time.Duration
	AutoMigrate bool
	ProjectID   string
}

// DefaultMaxConns is used when Config.MaxConns is zero.
const DefaultMaxConns int32 = 25

// DefaultConnTimeout is used when Config.ConnTimeout is zero.
const DefaultConnTimeout = 5 * time.Second

// ConfigFromEnv reads Config values from GATEWAY_POSTGRES_* env vars.
// It is a convenience for callers that don't want to plumb each field
// through their own config struct. projectID is passed in (rather than
// read from env) because identity already plumbs cfg.DefaultProjectID.
func ConfigFromEnv(projectID string) Config {
	return Config{
		DSN:         os.Getenv("GATEWAY_POSTGRES_DSN"),
		MaxConns:    envInt32("GATEWAY_POSTGRES_MAX_CONNS", DefaultMaxConns),
		ConnTimeout: time.Duration(envInt("GATEWAY_POSTGRES_CONN_TIMEOUT_MS", int(DefaultConnTimeout/time.Millisecond))) * time.Millisecond,
		AutoMigrate: envBool("GATEWAY_POSTGRES_AUTO_MIGRATE", false),
		ProjectID:   projectID,
	}
}

func (c *Config) applyDefaults() {
	if c.MaxConns == 0 {
		c.MaxConns = DefaultMaxConns
	}
	if c.ConnTimeout == 0 {
		c.ConnTimeout = DefaultConnTimeout
	}
}

func (c *Config) validate() error {
	if c == nil {
		return errors.New("postgres: nil config")
	}
	if strings.TrimSpace(c.DSN) == "" {
		return errors.New("postgres: DSN is required (set GATEWAY_POSTGRES_DSN)")
	}
	if strings.TrimSpace(c.ProjectID) == "" {
		return errors.New("postgres: ProjectID is required")
	}
	return nil
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

func envInt32(key string, def int32) int32 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return def
	}
	return int32(n)
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	return def
}
