-- 0044_add_self_service_tenants.up.sql
--
-- Self-service tenants: a signed-in user creates a tenant and becomes its
-- owner (CreateTenant). tenants.created_by names that user and is empty on
-- every tenant made another way (auto-formed from an email domain, or by an
-- operator). Like tenant_invitations.invited_by it is provenance and carries
-- no foreign key: deleting the creator neither blocks the delete nor
-- rewrites who made the tenant. It also bounds how many tenants one user may
-- create in a window, which is what the partial index serves.
--
-- The creator's membership records source 'created', so the source CHECK is
-- widened to admit it. The wider constraint is added NOT VALID: every
-- existing row satisfies it, so the scan is skipped and every later write is
-- checked.
--
-- The constant default makes ADD COLUMN a catalog-only change. The ALTERs
-- take an ACCESS EXCLUSIVE lock that the transaction holds to commit, so
-- reads and writes on both tables wait for the rest of the file, including
-- the index build. lock_timeout bounds the wait to acquire the lock, as in
-- 0034-0038: on timeout the file rolls back and version 44 is left dirty —
-- confirm tenants.created_by is absent, then `identity migrate force 43` and
-- `identity migrate` again.
SET LOCAL lock_timeout = '10s';

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS tenants_project_created_by_idx
    ON tenants (project_id, created_by, created_at_ms)
    WHERE created_by <> '';

ALTER TABLE tenant_memberships DROP CONSTRAINT IF EXISTS tenant_memberships_source_check;
ALTER TABLE tenant_memberships
    ADD CONSTRAINT tenant_memberships_source_check
    CHECK (source IN ('domain', 'invited', 'added', 'created')) NOT VALID;
