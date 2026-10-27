-- 0051_tenant_member_removals.up.sql
--
-- When a tenant owner or admin removes a member (RemoveTenantMember), that
-- is a decision about the person, not about their email. Until now a
-- person removed could join again at once through their verified email's
-- domain (JoinTenantByDomain) while the domain let people join.
-- tenant_member_removals records each removal, one row per (project,
-- tenant, user), and while it stands nothing makes the person a member
-- through the domain: neither a join by domain nor auto-formation. A
-- membership granted another way (an accepted invitation, an operator's
-- grant or recovery, a domain verification) deletes the row, since that
-- is a decision to let the person back in.
--
-- Like tenant_memberships, it is a governance table with no row-level
-- security (0016). Its rows go with the project, tenant or account they
-- name. The primary key serves every read; the user_id index serves the
-- cascade when an account is deleted, which is far more frequent than a
-- tenant or project being deleted.
--
-- Locks: CREATE TABLE with REFERENCES takes SHARE ROW EXCLUSIVE on
-- projects, tenants and users while it adds the foreign-key triggers. That
-- blocks writes to those tables, signups and account updates included, but
-- not reads, for as long as the catalog change takes. lock_timeout bounds
-- only the wait to acquire them, as in 0034-0050. While the CREATE waits
-- behind a transaction writing one of them, new writes to that table queue
-- behind it too, for up to that 10s. On a timeout the file rolls back and
-- version 51 is left dirty: `identity migrate force 50`, then
-- `identity migrate` again.
SET LOCAL lock_timeout = '10s';

CREATE TABLE IF NOT EXISTS tenant_member_removals (
    project_id     TEXT   NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id      TEXT   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id        TEXT   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    removed_at_ms  BIGINT NOT NULL,
    PRIMARY KEY (project_id, tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS tenant_member_removals_user_idx
    ON tenant_member_removals (user_id);
