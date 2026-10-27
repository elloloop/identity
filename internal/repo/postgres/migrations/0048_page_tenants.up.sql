-- 0048_page_tenants.up.sql
--
-- AdminListTenants pages through a project's tenants newest first, keyed on
-- (created_at_ms, id). This index serves that order, so a page reads only
-- its own rows rather than sorting every tenant of the project. It leads
-- with project_id, so it also serves every lookup by project alone, and the
-- project-only index 0013 made is dropped as redundant.
--
-- Locks: CREATE INDEX holds a SHARE lock on tenants, blocking writes to it
-- (auto-formation at signup, CreateTenant, domain verification) for the
-- build while reads continue; DROP INDEX then takes ACCESS EXCLUSIVE, which
-- blocks reads too, briefly, so it comes last. lock_timeout bounds only the
-- wait to acquire each lock, as in 0034-0047. On a timeout the file rolls
-- back and version 48 is left dirty: `identity migrate force 47`, then
-- `identity migrate` again. To keep writes flowing on a large table, build
-- the index first with CREATE INDEX CONCURRENTLY under the same name; the
-- IF NOT EXISTS guard makes this file skip the build.
SET LOCAL lock_timeout = '10s';

CREATE INDEX IF NOT EXISTS tenants_project_created_idx
    ON tenants (project_id, created_at_ms, id);

DROP INDEX IF EXISTS tenants_project_idx;
