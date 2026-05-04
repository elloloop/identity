// Package postgres provides a Postgres-backed implementation of
// service.Repository for the identity service.
//
// This is an alternative to the EntDB-backed repository. The two are
// interchangeable from the AuthService's point of view: both implement
// the same service.Repository interface.
//
// Why Postgres
//
// Postgres is well understood, ubiquitous in production environments,
// and ships with a mature ops toolkit (pg_dump, pg_basebackup, replicas,
// PITR via WAL archiving). It is the right default for teams that want
// to run identity without taking a dependency on the tenant-shard-db
// stack.
//
// Driver choice
//
// The implementation uses pgx/v5 directly (not via database/sql).
// pgxpool.Pool gives us a tuneable connection pool; pgx is also faster
// than database/sql and exposes Postgres-specific features (LISTEN /
// NOTIFY, COPY, JSONB native typing) that we may want later.
//
// Migrations
//
// Schema DDL lives under migrations/ and is applied via
// golang-migrate/migrate using the embed.FS source. By default New()
// runs pending migrations on first connect. Set Config.AutoMigrate to
// false (or GATEWAY_POSTGRES_AUTO_MIGRATE=false) to require explicit
// migrations from a deploy pipeline.
//
// Multi-tenancy
//
// Every table carries a tenant_id text not null column and uniqueness
// constraints are scoped to (tenant_id, ...). A pgRepository instance
// is constructed with a single tenant_id and writes/reads only that
// tenant's rows.
//
// Error mapping
//
// Postgres unique-violation errors (SQLSTATE 23505) are mapped to
// service.ErrAlreadyExists by errors.go::wrapPgErr. ErrNoRows is
// surfaced as a nil result (not an error), matching the existing
// in-memory and EntDB drivers.
package postgres
