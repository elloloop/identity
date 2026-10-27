-- 0049_drop_tenants_project_idx.down.sql
--
-- Puts back the project-only index 0013 made. CREATE INDEX holds a SHARE
-- lock on tenants for the build, so writes to tenants wait for it; this file
-- takes no other lock. lock_timeout bounds the wait to acquire it.
SET LOCAL lock_timeout = '10s';

CREATE INDEX IF NOT EXISTS tenants_project_idx
    ON tenants (project_id);
