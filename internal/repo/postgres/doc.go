// Package postgres provides a Postgres-backed implementation of
// service.Repository for the identity service.
//
// This is an alternative to the original graph-backed repository. The two are
// interchangeable from the AuthService's point of view: both implement
// the same service.Repository interface.
//
// # Why Postgres
//
// Postgres is well understood, ubiquitous in production environments,
// and ships with a mature ops toolkit (pg_dump, pg_basebackup, replicas,
// PITR via WAL archiving). It is the right default for teams that want
// to run identity without taking a dependency on the tenant-shard-db
// stack.
//
// # Driver choice
//
// The implementation uses pgx/v5 directly (not via database/sql).
// pgxpool.Pool gives us a tuneable connection pool; pgx is also faster
// than database/sql and exposes Postgres-specific features (LISTEN /
// NOTIFY, COPY, JSONB native typing) that we may want later.
//
// # Migrations
//
// Schema DDL lives under migrations/ and is applied via
// golang-migrate/migrate using the embed.FS source. By default New()
// does NOT run pending migrations on connect — production deploys run
// migrations out-of-band as a separate Job, so a rolling rollout never
// races two replicas to apply the same change. Set Config.AutoMigrate
// to true (or GATEWAY_POSTGRES_AUTO_MIGRATE=true) only for local dev
// and single-replica environments.
//
// # Project isolation (ADR-0002)
//
// The Project is identity's storage shard. Every data-plane table carries a
// project_id text not null column (FK to projects(id)) and uniqueness
// constraints are scoped to (project_id, ...). A pgRepository instance is
// bound to a single project_id and writes/reads only that project's rows;
// per-request scopes are derived via WithProject. The logical-tenant
// tenant_id columns on the governance tables (domains, login_policies,
// tenant_memberships, tenant_invitations) reference tenants(id) and are a
// separate concept from this storage shard.
//
// # Error mapping
//
// Postgres unique-violation errors (SQLSTATE 23505) are mapped to
// service.ErrAlreadyExists by errors.go::wrapPgErr. ErrNoRows is
// surfaced as a nil result (not an error), matching the existing
// in-memory driver.
package postgres
