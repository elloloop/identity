-- 0057_add_tenant_creator_operator_kind.down.sql
--
-- Dropping the column forgets which tenants a credential created: restoring
-- one with nobody governing it then needs an owner or admin appointed first.
SET LOCAL lock_timeout = '10s';

ALTER TABLE tenants
    DROP COLUMN creator_operator_kind;
