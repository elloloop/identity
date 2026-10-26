-- 0044_add_self_service_tenants.down.sql
--
-- A creator's membership becomes source 'added', the nearest older meaning
-- (a membership an owner's action made), so the original source CHECK holds
-- again; the creator keeps their role and status. Dropping created_by
-- forgets who created each self-service tenant, and with it the per-user
-- creation limit's history. lock_timeout bounds the wait for the locks, as
-- the up migration does.
SET LOCAL lock_timeout = '10s';

UPDATE tenant_memberships SET source = 'added' WHERE source = 'created';

ALTER TABLE tenant_memberships DROP CONSTRAINT IF EXISTS tenant_memberships_source_check;
ALTER TABLE tenant_memberships
    ADD CONSTRAINT tenant_memberships_source_check
    CHECK (source IN ('domain', 'invited', 'added'));

DROP INDEX IF EXISTS tenants_project_created_by_idx;
ALTER TABLE tenants
    DROP COLUMN IF EXISTS created_by;
