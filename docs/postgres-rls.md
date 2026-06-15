# Postgres Row-Level Security (RLS) — operator guide

The Postgres backend enforces project isolation with **two independent
boundaries**:

1. **Application predicate (primary).** Every data-plane query the driver
   issues carries a `WHERE project_id = $1` clause, bound at the
   `RepositoryForProject` boundary (ADR-0002).
2. **Row-Level Security (defense-in-depth).** Migration `0016` enables RLS
   on every data-plane table with a policy:

   ```sql
   USING (project_id = current_setting('app.current_project_id', true))
   ```

   Even a query that *forgets* the predicate — a future code path, an ad-hoc
   `psql` session, a SQL-injection — can only ever touch rows of the project
   bound to the current connection.

## How the GUC is set

The driver sets the `app.current_project_id` session GUC on **every
connection it checks out of the pool**, scoped to the project the acquiring
repository is bound to. This is wired through the pgxpool `PrepareConn`
hook (`internal/repo/postgres/rls.go`), which runs on every `Acquire` —
including the implicit acquire inside `pool.Query` / `pool.Exec` /
`pool.QueryRow` / `pool.Begin`, and the transaction `ExecuteAtomic` opens.
Because the hook **always overwrites** the GUC with the acquiring
repository's project, a pooled connection reused by a different project can
never carry a stale value into that project's query.

**Fail closed.** The policy uses `current_setting(…, true)` (`missing_ok =
true`), so an *unset* GUC evaluates to SQL `NULL`. `project_id = NULL` is
never true, so a connection that never set the GUC matches **zero rows** on
every table. A missing `SET` can only ever cause "zero rows", never a
cross-project leak.

## Role requirement (REQUIRED)

> **The database role identity connects as MUST NOT have the `BYPASSRLS`
> attribute, and SHOULD NOT be a Postgres superuser.**

A superuser, and any role with `BYPASSRLS`, ignores every RLS policy. If
identity connects as such a role, migration 0016 is silently a no-op and
the only remaining boundary is the application predicate.

The migration uses `FORCE ROW LEVEL SECURITY` so the policy also applies to
the **table owner** (a table's owner is otherwise exempt). This makes the
boundary real in the common single-role deployment where identity owns its
tables — but `FORCE` does **not** override `BYPASSRLS`. Verify:

```sql
-- Must report rolbypassrls = f and rolsuper = f
SELECT rolname, rolsuper, rolbypassrls
  FROM pg_roles
 WHERE rolname = current_user;
```

A hardened deployment runs migrations as an owner/DDL role and serves
traffic as a separate, least-privilege login role that owns nothing and has
neither `SUPERUSER` nor `BYPASSRLS`. In that setup `FORCE` is belt-and-
suspenders; the runtime role is already subject to the policy.

## What is NOT covered by RLS

Control-plane tables are platform-global by design and intentionally have
**no `project_id` and no RLS**: `projects`, `tenants`, `domains`,
`project_credentials`, `project_auth_domains`, `platform_admins`,
`login_policies`, `tenant_memberships`, `tenant_invitations`. A request
resolves its project from these tables *before* any data-plane query runs.

`TRUNCATE` is governed by table privileges, not row policies, so RLS never
applies to it (relevant only to admin/test truncation paths).

## Proof

`internal/repo/postgres/rls_test.go` (`runRLSProof`) writes a row under
project A through the real repository, then drives the policy from a
**separate raw connection** with a **predicate-less** `SELECT * FROM
users`: with the GUC set to B (or unset) it sees zero rows; with the GUC set
to A it sees A's row. Because the query has no `project_id` filter, a
non-empty result for B could only come from the database exposing the row —
so the test proves RLS itself, not the Go-side filter. It runs as the
untagged `TestPostgres_RLS_Smoke` (against `GATEWAY_TEST_POSTGRES_DSN`) and
as the `dockerpostgres`-tagged `TestPostgres_RLS_Container`.
