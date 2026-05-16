-- 0006_add_organizations.up.sql
--
-- Identity-layer Organization + OrganizationMembership tables for
-- `mode=multi` deployments (see docs/IDENTITY.md). Both rows live
-- inside their owning tenant scope (every row carries `tenant_id`
-- like every other table in this schema); the (organization, user)
-- pair is enforced unique within a tenant via a composite unique
-- index on org_members.

CREATE TABLE IF NOT EXISTS organizations (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    slug            TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    owner_user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at_ms   BIGINT NOT NULL,
    updated_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS organizations_tenant_slug_uidx
    ON organizations (tenant_id, slug);
CREATE INDEX IF NOT EXISTS organizations_tenant_owner_idx
    ON organizations (tenant_id, owner_user_id);

CREATE TABLE IF NOT EXISTS organization_members (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            TEXT NOT NULL DEFAULT 'member'
                       CHECK (role IN ('admin','member','guest')),
    created_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS org_members_tenant_org_user_uidx
    ON organization_members (tenant_id, organization_id, user_id);
CREATE INDEX IF NOT EXISTS org_members_tenant_user_idx
    ON organization_members (tenant_id, user_id);
