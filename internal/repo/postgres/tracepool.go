package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"

	"github.com/elloloop/identity/internal/observability"
)

// tracedPool wraps *pgxpool.Pool with per-call OpenTelemetry spans.
// Only the methods the postgres repository actually exercises (Query,
// QueryRow, Exec, Begin, Close) are surfaced — keeping the surface
// small avoids accidentally calling untraced pool methods and is
// trivial to grow if a new method is genuinely needed. When OTel is
// disabled the global no-op tracer is in effect and the only cost is
// the dispatch through observability.StartClient.
//
// A tracedPool also carries the projectID it is bound to and injects it
// into the context of every pool operation (withProjectGUC) so the pool's
// PrepareConn hook sets the app.current_project_id GUC the migration-0016
// RLS policies read. WithProject derives a new tracedPool view that shares
// the same underlying *pgxpool.Pool but carries a different projectID, so
// two project scopes can share one connection pool without one scope's GUC
// leaking into the other's queries (PrepareConn always re-sets it at
// acquire time — see rls.go).
type tracedPool struct {
	inner     *pgxpool.Pool
	projectID string
}

func newTracedPool(p *pgxpool.Pool, projectID string) *tracedPool {
	return &tracedPool{inner: p, projectID: projectID}
}

// forProject returns a tracedPool view sharing this pool's underlying
// connection pool but bound to a different project. The shared *pgxpool.Pool
// is NOT duplicated, so the derived view must not be Closed independently.
func (p *tracedPool) forProject(projectID string) *tracedPool {
	return &tracedPool{inner: p.inner, projectID: projectID}
}

// scopeCtx injects this pool's bound project into ctx so the PrepareConn
// hook scopes the acquired connection's RLS GUC to it.
func (p *tracedPool) scopeCtx(ctx context.Context) context.Context {
	return withProjectGUC(ctx, p.projectID)
}

func (p *tracedPool) Close() {
	if p == nil || p.inner == nil {
		return
	}
	p.inner.Close()
}

func (p *tracedPool) Ping(ctx context.Context) error {
	ctx = p.scopeCtx(ctx)
	ctx, end := observability.StartClient(ctx, "postgres.Ping",
		attribute.String("db.system", "postgresql"),
	)
	err := p.inner.Ping(ctx)
	end(err)
	return err
}

func (p *tracedPool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	ctx = p.scopeCtx(ctx)
	ctx, end := observability.StartClient(ctx, "postgres.Exec", sqlAttrs(sql)...)
	tag, err := p.inner.Exec(ctx, sql, args...)
	end(err)
	return tag, err
}

func (p *tracedPool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	ctx = p.scopeCtx(ctx)
	ctx, end := observability.StartClient(ctx, "postgres.Query", sqlAttrs(sql)...)
	rows, err := p.inner.Query(ctx, sql, args...)
	// rows are streamed and the caller closes them — we end the span
	// at the call boundary anyway so the span captures statement-prep
	// latency without leaving the span open for the result iterator.
	end(err)
	return rows, err
}

func (p *tracedPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	ctx = p.scopeCtx(ctx)
	ctx, end := observability.StartClient(ctx, "postgres.QueryRow", sqlAttrs(sql)...)
	row := p.inner.QueryRow(ctx, sql, args...)
	end(nil)
	return row
}

func (p *tracedPool) Begin(ctx context.Context) (pgx.Tx, error) {
	ctx = p.scopeCtx(ctx)
	ctx, end := observability.StartClient(ctx, "postgres.Begin",
		attribute.String("db.system", "postgresql"),
	)
	tx, err := p.inner.Begin(ctx)
	end(err)
	return tx, err
}

func sqlAttrs(sql string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("db.system", "postgresql"),
		attribute.String("db.statement", truncSQL(sql)),
	}
}

const maxSQLAttrLen = 512

func truncSQL(s string) string {
	if len(s) <= maxSQLAttrLen {
		return s
	}
	return s[:maxSQLAttrLen] + "…"
}
