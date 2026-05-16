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
type tracedPool struct {
	inner *pgxpool.Pool
}

func newTracedPool(p *pgxpool.Pool) *tracedPool {
	return &tracedPool{inner: p}
}

func (p *tracedPool) Close() {
	if p == nil || p.inner == nil {
		return
	}
	p.inner.Close()
}

func (p *tracedPool) Ping(ctx context.Context) error {
	ctx, end := observability.StartClient(ctx, "postgres.Ping",
		attribute.String("db.system", "postgresql"),
	)
	err := p.inner.Ping(ctx)
	end(err)
	return err
}

func (p *tracedPool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	ctx, end := observability.StartClient(ctx, "postgres.Exec", sqlAttrs(sql)...)
	tag, err := p.inner.Exec(ctx, sql, args...)
	end(err)
	return tag, err
}

func (p *tracedPool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	ctx, end := observability.StartClient(ctx, "postgres.Query", sqlAttrs(sql)...)
	rows, err := p.inner.Query(ctx, sql, args...)
	// rows are streamed and the caller closes them — we end the span
	// at the call boundary anyway so the span captures statement-prep
	// latency without leaving the span open for the result iterator.
	end(err)
	return rows, err
}

func (p *tracedPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	ctx, end := observability.StartClient(ctx, "postgres.QueryRow", sqlAttrs(sql)...)
	row := p.inner.QueryRow(ctx, sql, args...)
	end(nil)
	return row
}

func (p *tracedPool) Begin(ctx context.Context) (pgx.Tx, error) {
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
