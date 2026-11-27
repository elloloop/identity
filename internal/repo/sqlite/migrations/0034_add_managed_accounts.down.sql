-- 0034_add_managed_accounts.down.sql

ALTER TABLE users DROP COLUMN setup_epoch;
ALTER TABLE users DROP COLUMN set_up_at_ms;
ALTER TABLE users DROP COLUMN managed_by_tenant_id;
