-- 0052_tenant_member_removals.down.sql
--
-- Drops the removal records. A person removed from a tenant can then join
-- it again through their domain while the domain lets people join, which
-- is what a release without them does. lock_timeout bounds the wait for the
-- locks, as the up migration does.
SET LOCAL lock_timeout = '10s';

DROP TABLE IF EXISTS tenant_member_removals;
