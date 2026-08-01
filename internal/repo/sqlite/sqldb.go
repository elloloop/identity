package sqlite

import (
	"context"
	"database/sql"
	"errors"
)

// sqldb is a thin façade over *sql.DB that mirrors the small slice of the
// pgx pool API the store methods use (QueryRow / Query / Exec / Begin). It
// exists so the SQLite store implementations stay line-for-line parallel
// with the Postgres driver: same SQL strings, same `$N` placeholders, same
// row-scan shape.
//
// modernc.org/sqlite natively understands Postgres-style numbered `$N`
// placeholders (mapping the Nth arg to every `$N` occurrence, so a reused
// `$3` in a CAS UPDATE binds the same value), so the SQL strings pass
// through verbatim — no placeholder rewriting is needed.
type sqldb struct {
	db *sql.DB
}

// querier is the shared surface of *sql.DB and *sql.Tx, so execContext /
// queryContext work transparently inside or outside a transaction.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// scanner is satisfied by both row and rows, so the shared scanX helpers
// decode a single-row QueryRow result or a row pulled from a multi-row
// iteration identically (mirroring how the postgres driver passes a
// pgx.Row to its scan helpers).
type scanner interface {
	Scan(dest ...any) error
}

// row mirrors pgx.Row: a single deferred-error Scan.
type row struct {
	r *sql.Row
}

func (r row) Scan(dest ...any) error { return r.r.Scan(dest...) }

// rows mirrors the subset of pgx.Rows the stores use (Next / Scan / Close /
// Err).
type rows struct {
	r *sql.Rows
}

func (rs rows) Next() bool          { return rs.r.Next() }
func (rs rows) Scan(d ...any) error { return rs.r.Scan(d...) }
func (rs rows) Close()              { _ = rs.r.Close() }
func (rs rows) Err() error          { return rs.r.Err() }

// commandTag mirrors pgx.CommandTag's RowsAffected accessor, the only piece
// the stores rely on (for CAS-style single-winner UPDATE/DELETE checks).
type commandTag struct {
	affected int64
}

func (t commandTag) RowsAffected() int64 { return t.affected }

func (s *sqldb) QueryRow(ctx context.Context, q string, args ...any) row {
	return queryRowOn(ctx, s.db, q, args...)
}

func (s *sqldb) Query(ctx context.Context, q string, args ...any) (rows, error) {
	return queryOn(ctx, s.db, q, args...)
}

func (s *sqldb) Exec(ctx context.Context, q string, args ...any) (commandTag, error) {
	return execOn(ctx, s.db, q, args...)
}

// tx wraps *sql.Tx with the same façade so DeleteUser's multi-statement
// cascade can run atomically, exactly like the Postgres pgx.Tx path.
type tx struct {
	t *sql.Tx
}

func (s *sqldb) Begin(ctx context.Context) (*tx, error) {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &tx{t: t}, nil
}

func (t *tx) Exec(ctx context.Context, q string, args ...any) (commandTag, error) {
	return execOn(ctx, t.t, q, args...)
}

// Query lets a transaction read the rows it is about to modify — the
// batched anonymous-user sweep selects its victims and deletes them and
// their non-FK child rows in one transaction.
func (t *tx) Query(ctx context.Context, q string, args ...any) (rows, error) {
	return queryOn(ctx, t.t, q, args...)
}

func (t *tx) Commit(ctx context.Context) error   { return t.t.Commit() }
func (t *tx) Rollback(ctx context.Context) error { return t.t.Rollback() }

func queryRowOn(ctx context.Context, q querier, query string, args ...any) row {
	return row{r: q.QueryRowContext(ctx, query, args...)}
}

func queryOn(ctx context.Context, q querier, query string, args ...any) (rows, error) {
	r, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return rows{}, err
	}
	return rows{r: r}, nil
}

func execOn(ctx context.Context, q querier, query string, args ...any) (commandTag, error) {
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return commandTag{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return commandTag{}, err
	}
	return commandTag{affected: n}, nil
}

// noRows reports whether err is the canonical "scanned a row that wasn't
// there". database/sql returns sql.ErrNoRows from Row.Scan, the SQLite
// analogue of pgx.ErrNoRows.
func noRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
