-- 0013_add_projects_tenants_domains.up.sql
--
-- Redesign foundation (additive). Adds the control-plane registry
-- (projects, credentials, auth-domains, platform admins) and the
-- per-project tenant-governance tables (tenants, domains, login policies,
-- memberships, invitations). NEW tables only — existing tables are
-- untouched here; the project_id backfill on existing tables is a later
-- expand-backfill-contract migration. See docs/redesign/schema.md.
--
-- Conventions match 0001_init: TEXT PKs (caller-supplied
-- gen_random_uuid()::text), BIGINT epoch-ms timestamps (*_at_ms; 0 = never),
-- TEXT+CHECK enums, JSONB config, and project_id as the leading column of
-- every data-plane index.

-- ── Control plane ──────────────────────────────────────────────────────

CREATE TABLE projects (
    id                TEXT PRIMARY KEY,
    storage_scope_id  TEXT NOT NULL,
    name              TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active','suspended')),
    config_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at_ms     BIGINT NOT NULL,
    updated_at_ms     BIGINT NOT NULL
);
CREATE UNIQUE INDEX projects_storage_scope_uidx
    ON projects (storage_scope_id);
CREATE INDEX projects_status_idx
    ON projects (status);

CREATE TABLE project_credentials (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL
                       CHECK (kind IN ('publishable','secret','mtls')),
    public_id       TEXT NOT NULL,
    secret_hash     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','revoked')),
    created_at_ms   BIGINT NOT NULL,
    last_used_at_ms BIGINT NOT NULL DEFAULT 0,
    revoked_at_ms   BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX project_credentials_public_id_uidx
    ON project_credentials (public_id);
CREATE INDEX project_credentials_project_idx
    ON project_credentials (project_id);
CREATE INDEX project_credentials_project_status_idx
    ON project_credentials (project_id, status);

CREATE TABLE project_auth_domains (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hostname        TEXT NOT NULL,
    is_primary      BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at_ms  BIGINT NOT NULL DEFAULT 0,
    created_at_ms   BIGINT NOT NULL
);
-- Globally unique hostname: one host resolves to exactly one project.
CREATE UNIQUE INDEX project_auth_domains_hostname_uidx
    ON project_auth_domains (lower(hostname));
-- At most one primary hostname per project (drives email/oauth link building).
CREATE UNIQUE INDEX project_auth_domains_primary_uidx
    ON project_auth_domains (project_id) WHERE is_primary;
CREATE INDEX project_auth_domains_project_idx
    ON project_auth_domains (project_id);

CREATE TABLE platform_admins (
    id               TEXT PRIMARY KEY,
    email            TEXT NOT NULL,
    password_hash    TEXT NOT NULL DEFAULT '',
    totp_required    BOOLEAN NOT NULL DEFAULT FALSE,
    status           TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','suspended')),
    created_at_ms    BIGINT NOT NULL,
    last_login_at_ms BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX platform_admins_email_uidx
    ON platform_admins (lower(email));
CREATE INDEX platform_admins_status_idx
    ON platform_admins (status);

-- ── Per-project data plane ─────────────────────────────────────────────

CREATE TABLE tenants (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name            TEXT NOT NULL DEFAULT '',
    primary_domain  TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'latent'
                       CHECK (status IN ('latent','claimed','suspended')),
    created_at_ms   BIGINT NOT NULL,
    updated_at_ms   BIGINT NOT NULL
);
CREATE INDEX tenants_project_idx
    ON tenants (project_id);
CREATE INDEX tenants_project_primary_domain_idx
    ON tenants (project_id, lower(primary_domain));
CREATE INDEX tenants_project_status_idx
    ON tenants (project_id, status);

CREATE TABLE domains (
    id                   TEXT PRIMARY KEY,
    project_id           TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain               TEXT NOT NULL,
    verification_method  TEXT NOT NULL
                            CHECK (verification_method IN ('dns_txt','email')),
    status               TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','verified','failed')),
    verified_at_ms       BIGINT NOT NULL DEFAULT 0,
    created_at_ms        BIGINT NOT NULL,
    updated_at_ms        BIGINT NOT NULL
);
-- One tenant per email domain within a project.
CREATE UNIQUE INDEX domains_project_domain_uidx
    ON domains (project_id, lower(domain));
CREATE INDEX domains_project_tenant_idx
    ON domains (project_id, tenant_id);
CREATE INDEX domains_project_status_idx
    ON domains (project_id, status);

CREATE TABLE login_policies (
    id                   TEXT PRIMARY KEY,
    project_id           TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    allowed_methods      TEXT NOT NULL DEFAULT '',
    sso_required         BOOLEAN NOT NULL DEFAULT FALSE,
    sso_connection_json  JSONB NOT NULL DEFAULT '{}'::jsonb,
    require_2fa          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_ms        BIGINT NOT NULL,
    updated_at_ms        BIGINT NOT NULL
);
CREATE UNIQUE INDEX login_policies_project_tenant_uidx
    ON login_policies (project_id, tenant_id);

CREATE TABLE tenant_memberships (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source          TEXT NOT NULL
                       CHECK (source IN ('domain','invited','added')),
    role            TEXT NOT NULL DEFAULT 'member'
                       CHECK (role IN ('member','admin','owner')),
    status          TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','pending','inactive')),
    created_at_ms   BIGINT NOT NULL,
    updated_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX tenant_memberships_project_tenant_user_uidx
    ON tenant_memberships (project_id, tenant_id, user_id);
CREATE INDEX tenant_memberships_project_user_idx
    ON tenant_memberships (project_id, user_id);
CREATE INDEX tenant_memberships_project_tenant_idx
    ON tenant_memberships (project_id, tenant_id);

CREATE TABLE tenant_invitations (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    email           TEXT NOT NULL,
    -- invited_by is provenance, intentionally NOT an FK (mirrors
    -- users.invited_by) so deleting the inviter neither blocks the delete
    -- nor rewrites the invitation's audit trail.
    invited_by      TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'member'
                       CHECK (role IN ('member','admin','owner')),
    status          TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','accepted','revoked','expired')),
    expires_at_ms   BIGINT NOT NULL,
    accepted_at_ms  BIGINT NOT NULL DEFAULT 0,
    created_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX tenant_invitations_project_token_uidx
    ON tenant_invitations (project_id, token_hash);
-- One open invite per (project, tenant, email); defense-in-depth. Authoritative
-- enforcement is the atomic revoke-then-insert at the repo boundary (entdb/
-- memory cannot express partial-unique, and must match these semantics in the
-- conformance suite).
CREATE UNIQUE INDEX tenant_invitations_open_email_uidx
    ON tenant_invitations (project_id, tenant_id, lower(email))
    WHERE status = 'pending';
CREATE INDEX tenant_invitations_project_tenant_idx
    ON tenant_invitations (project_id, tenant_id);
CREATE INDEX tenant_invitations_project_expires_idx
    ON tenant_invitations (project_id, expires_at_ms);
