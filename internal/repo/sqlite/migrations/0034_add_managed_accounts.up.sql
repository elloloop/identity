-- 0034_add_managed_accounts.up.sql
--
-- SQLite mirror of postgres 0068's users columns. SQLite has no tenants, so
-- no account here is managed; the columns keep the users shape identical
-- across drivers.
ALTER TABLE users ADD COLUMN managed_by_tenant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN set_up_at_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN setup_epoch INTEGER NOT NULL DEFAULT 0;
