-- 0049_drop_tenants_project_idx.up.sql
--
-- Drops tenants_project_idx (project_id), which 0048's
-- tenants_project_created_idx (project_id, created_at_ms, id) makes
-- redundant: every lookup by project alone uses the new index's leading
-- column.
--
-- This runs in its own file, so in its own transaction, after 0048 has
-- committed and released its SHARE lock. Taking ACCESS EXCLUSIVE in the
-- same transaction as that build would upgrade the lock, and could deadlock
-- against a request that reads tenants and then inserts into it
-- (auto-formation at signup, CreateTenant).
--
-- Locks: DROP INDEX takes ACCESS EXCLUSIVE on tenants for a moment. It waits
-- for transactions already using tenants to finish, and while it waits, new
-- reads and writes of tenants queue behind it. lock_timeout bounds that wait
-- to 10s. On a timeout the file rolls back and version 49 is left dirty:
-- `identity migrate force 48`, then `identity migrate` again.
SET LOCAL lock_timeout = '10s';

DROP INDEX IF EXISTS tenants_project_idx;
