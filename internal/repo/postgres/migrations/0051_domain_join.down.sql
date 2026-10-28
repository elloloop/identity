-- 0051_domain_join.down.sql
--
-- Drops the join setting. Every domain then admits nobody by request, which
-- is what a release without JoinTenantByDomain does; the memberships made
-- by joining stay. lock_timeout bounds the wait for the lock, as the up
-- migration does.
SET LOCAL lock_timeout = '10s';

ALTER TABLE domains DROP COLUMN IF EXISTS allow_join;
