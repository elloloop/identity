-- 0057_add_tenant_creator_operator_kind.up.sql
--
-- tenants gains what authorized the AdminCreateTenant that made a tenant:
-- 'admin_secret', 'tenant_operator' for a tenant_operator credential, or ''
-- for a tenant made any other way and every tenant from before this column.
-- A tenant_operator credential may restore a suspended tenant a credential
-- created even when nobody governs it.
--
-- The constant default adds the column without rewriting the table. The CHECK
-- is added NOT VALID: every existing row holds the default '', which passes
-- it, so it is not scanned, and every later write is checked. Each ALTER
-- takes ACCESS EXCLUSIVE on tenants only for a catalog change; lock_timeout
-- bounds the wait to acquire it.
SET LOCAL lock_timeout = '10s';

ALTER TABLE tenants
    ADD COLUMN creator_operator_kind TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants
    ADD CONSTRAINT tenants_creator_operator_kind_check
    CHECK (creator_operator_kind IN ('', 'admin_secret', 'tenant_operator')) NOT VALID;
