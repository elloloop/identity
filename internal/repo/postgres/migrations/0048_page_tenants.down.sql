-- 0048_page_tenants.down.sql
--
-- Puts back the project-only index and drops the paging one, after which
-- AdminListTenants sorts a project's tenants on every page. lock_timeout
-- bounds the wait for each lock, as the up migration does.
SET LOCAL lock_timeout = '10s';

CREATE INDEX IF NOT EXISTS tenants_project_idx
    ON tenants (project_id);

DROP INDEX IF EXISTS tenants_project_created_idx;
