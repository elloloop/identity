-- 0070_add_managed_help_notices.up.sql
--
-- A help request (RequestAdminHelp) about an account a tenant manages goes to
-- that tenant's owners and admins. managed_help_notices records each notice
-- sent, so a tenant is told about one account at most once a day, and the
-- notices one tenant is sent, and those one source causes, stay under their
-- daily caps. source_key is an HMAC of the client address (an IPv6 client
-- as its /64) under a server secret, never the address.
-- Rows older than a day are deleted by the next request for the tenant.
--
-- Like tenant_memberships, it is a governance table with no row-level
-- security (0016). Its rows go with the project, tenant or account they
-- name. The tenant index serves every count; the user_id index serves the
-- cascade when an account is deleted.
--
-- Locks: CREATE TABLE with REFERENCES takes SHARE ROW EXCLUSIVE on projects,
-- tenants and users while it adds the foreign-key triggers, blocking writes
-- to them, not reads, for as long as the catalog change takes. lock_timeout
-- bounds the wait to acquire them, as in 0052. On a timeout the file rolls
-- back and version 70 is left dirty: `identity migrate force 69`, then
-- `identity migrate` again.
SET LOCAL lock_timeout = '10s';

CREATE TABLE IF NOT EXISTS managed_help_notices (
    id             TEXT   PRIMARY KEY,
    project_id     TEXT   NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id      TEXT   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id        TEXT   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_key     TEXT   NOT NULL,
    created_at_ms  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS managed_help_notices_tenant_idx
    ON managed_help_notices (project_id, tenant_id, created_at_ms);
CREATE INDEX IF NOT EXISTS managed_help_notices_user_idx
    ON managed_help_notices (user_id);
