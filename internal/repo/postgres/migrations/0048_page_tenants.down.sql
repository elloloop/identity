-- 0048_page_tenants.down.sql
--
-- Drops the paging index, after which AdminListTenants sorts a project's
-- tenants on every page. 0049's down migration has already put back the
-- project-only index. DROP INDEX takes ACCESS EXCLUSIVE on tenants briefly;
-- lock_timeout bounds the wait for it, as the up migration does.
SET LOCAL lock_timeout = '10s';

DROP INDEX IF EXISTS tenants_project_created_idx;
