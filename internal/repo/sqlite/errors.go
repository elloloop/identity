package sqlite

import (
	"errors"
	"fmt"

	sqlitelib "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/elloloop/identity/internal/service"
)

// wrapErr inspects a modernc SQLite error and maps a uniqueness violation to
// service.ErrAlreadyExists, mirroring the postgres driver's 23505 -> sentinel
// translation so the conformance suite sees identical error semantics across
// backends. Anything else is wrapped verbatim with the operation name so the
// call site keeps its %w context.
func wrapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if isUniqueViolation(err) {
		return fmt.Errorf("sqlite: %s: %w", op, service.ErrAlreadyExists)
	}
	return fmt.Errorf("sqlite: %s: %w", op, err)
}

// isUniqueViolation reports whether err carries SQLite's UNIQUE / PRIMARY KEY
// constraint extended result code (the analogue of Postgres SQLSTATE 23505).
// Callers that format their own sentinel (e.g. "sid %q already exists") use
// this instead of wrapErr.
func isUniqueViolation(err error) bool {
	var se *sqlitelib.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	default:
		return false
	}
}
