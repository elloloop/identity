package postgres

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/elloloop/identity/internal/service"
)

// pgErrCodeUniqueViolation is the SQLSTATE for unique_violation in
// Postgres (and the SQL standard). It is the only Postgres-specific
// error code identity needs to translate at the moment; further codes
// (foreign_key_violation, check_violation, …) will join this map as
// the surface area grows.
const pgErrCodeUniqueViolation = "23505"

// wrapPgErr inspects a pgx error and maps recognised SQLSTATEs to the
// service-layer sentinel errors. Unrecognised errors are returned
// unchanged so callers can wrap them with their own context.
//
// The current mapping is intentionally minimal:
//
//	23505 unique_violation -> service.ErrAlreadyExists
//
// Anything else falls through to %w-style wrapping at the call site.
func wrapPgErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgErrCodeUniqueViolation {
		return fmt.Errorf("postgres: %s: %w", op, service.ErrAlreadyExists)
	}
	return fmt.Errorf("postgres: %s: %w", op, err)
}
