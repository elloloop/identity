-- 0057_add_tenant_creator_credential_kind.up.sql
--
-- tenants gains what authorized the AdminCreateTenant that made a tenant:
-- 'admin_secret', 'tenant_operator' for a tenant_operator credential, or ''
-- for a tenant made any other way and every tenant from before this column.
-- A tenant_operator credential may restore a suspended tenant a credential
-- created even when nobody governs it. The column's constant default adds it
-- without rewriting the table; the CHECK scans it once under ACCESS
-- EXCLUSIVE, bounded by the lock timeout.
SET LOCAL lock_timeout = '10s';

ALTER TABLE tenants
    ADD COLUMN creator_credential_kind TEXT NOT NULL DEFAULT ''
        CONSTRAINT tenants_creator_credential_kind_check
        CHECK (creator_credential_kind IN ('', 'admin_secret', 'tenant_operator'));
