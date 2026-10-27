-- 0048_page_tenants.up.sql
--
-- AdminListTenants pages through a project's tenants newest first, keyed on
-- (created_at_ms, id). This index serves that order, so a page reads only
-- its own rows rather than sorting every tenant of the project. It leads
-- with project_id, so it also serves every lookup by project alone; 0049
-- drops the project-only index 0013 made, in its own transaction.
--
-- Locks: this file takes one lock and never upgrades it. CREATE INDEX holds
-- a SHARE lock on tenants until the file commits: reads continue, and every
-- write to tenants (auto-formation at signup, CreateTenant,
-- AdminCreateTenant, a domain's verification) waits for the build to end.
-- lock_timeout bounds only the wait to acquire that lock, behind a
-- transaction already writing tenants, as in 0034-0047.
--
-- Failure modes: a lock timeout, or a build that fails (a cancelled
-- statement, a full disk), rolls the file back and leaves version 48 dirty:
-- `identity migrate force 47`, then `identity migrate` again.
--
-- To keep writes flowing on a large table, build the index first with
-- CREATE INDEX CONCURRENTLY under the same name and definition, and the
-- IF NOT EXISTS guard skips the build. A concurrent build that fails leaves
-- an INVALID index under that name, which the guard skips too: check
-- pg_index.indisvalid first and rebuild it if false (docs/UPGRADE.md).
SET LOCAL lock_timeout = '10s';

CREATE INDEX IF NOT EXISTS tenants_project_created_idx
    ON tenants (project_id, created_at_ms, id);
