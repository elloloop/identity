-- 0001_init.up.sql
--
-- Initial schema for the Postgres-backed identity repository.
--
-- Data-shape decisions (kept here so any future change has a single
-- source of historical context):
--
--   * IDs. Every table uses a TEXT primary key, not UUID. Internally we
--     populate it with `gen_random_uuid()::text` so callers see normal
--     UUID strings, but the column type stays TEXT because the service
--     layer treats node IDs as opaque strings and the in-memory driver
--     also issues string IDs.
--     (gen_random_uuid lives in pgcrypto on PG <13; on PG 13+ it is in
--     core, so no extension is required for postgres:16-alpine.)
--
--   * Tenant scoping. Every row carries `tenant_id text not null`. All
--     unique constraints that would naively be on (column) are instead
--     scoped to (tenant_id, column). This matches identity's existing
--     multi-tenant model where `cfg.DefaultTenantID` partitions a
--     deployment.
--
--   * Timestamps. Stored as bigint epoch milliseconds, NOT
--     timestamptz. The service layer already passes int64 ms
--     everywhere (see service.RefreshTokenRecord et al), so converting
--     would only introduce an extra round-trip.
--
--   * Soft / single-use semantics. *_consumed_at_ms columns default to
--     0 (= unconsumed) instead of NULL so the service layer's
--     "consumed_at == 0" predicate from auth.go translates straight to
--     SQL.
--
--   * Enums. Roles, statuses, etc. are stored as plain TEXT columns
--     with CHECK constraints rather than Postgres ENUM types, because
--     adding a new enum value to a TEXT+CHECK column is a one-line
--     migration whereas ALTER TYPE ... ADD VALUE in PG is more
--     painful (and not transactional in older versions).
--
--   * Audit details. `details` is JSONB so callers can serialize
--     arbitrary map[string]any payloads.

CREATE TABLE IF NOT EXISTS users (
    id                     TEXT PRIMARY KEY,
    tenant_id              TEXT NOT NULL,
    email                  TEXT NOT NULL,
    name                   TEXT NOT NULL DEFAULT '',
    role                   TEXT NOT NULL DEFAULT 'member'
                              CHECK (role IN ('admin','member','guest')),
    avatar_url             TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active','invited','deactivated','suspended')),
    recovery_email         TEXT NOT NULL DEFAULT '',
    password_hash          TEXT NOT NULL DEFAULT '',
    quota_bytes            BIGINT NOT NULL DEFAULT 0,
    totp_required          BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_count     BIGINT NOT NULL DEFAULT 0,
    locked_until_ms        BIGINT NOT NULL DEFAULT 0,
    email_verified         BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified_at_ms   BIGINT NOT NULL DEFAULT 0,
    invited_by             TEXT NOT NULL DEFAULT '',
    invited_at_ms          BIGINT NOT NULL DEFAULT 0,
    last_login_at_ms       BIGINT NOT NULL DEFAULT 0,
    deactivated_at_ms      BIGINT NOT NULL DEFAULT 0,
    created_at_ms          BIGINT NOT NULL,
    updated_at_ms          BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_email_uidx ON users (tenant_id, lower(email));
CREATE INDEX IF NOT EXISTS users_tenant_status_idx ON users (tenant_id, status);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    token_hash        TEXT NOT NULL,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_info       TEXT NOT NULL DEFAULT '',
    device_name       TEXT NOT NULL DEFAULT '',
    ip_address        TEXT NOT NULL DEFAULT '',
    user_agent        TEXT NOT NULL DEFAULT '',
    expires_at_ms     BIGINT NOT NULL,
    created_at_ms     BIGINT NOT NULL,
    last_used_at_ms   BIGINT NOT NULL DEFAULT 0,
    consumed_at_ms    BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_tenant_hash_uidx
    ON refresh_tokens (tenant_id, token_hash);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx
    ON refresh_tokens (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS sessions (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_id  TEXT REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    ip_address        TEXT NOT NULL DEFAULT '',
    user_agent        TEXT NOT NULL DEFAULT '',
    created_at_ms     BIGINT NOT NULL,
    last_seen_at_ms   BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email           TEXT NOT NULL DEFAULT '',
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL,
    consumed_at_ms  BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS prt_tenant_hash_uidx
    ON password_reset_tokens (tenant_id, token_hash);
CREATE INDEX IF NOT EXISTS prt_user_idx
    ON password_reset_tokens (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    user_id         TEXT NOT NULL DEFAULT '',
    email           TEXT NOT NULL,
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL,
    consumed_at_ms  BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS evt_tenant_hash_uidx
    ON email_verification_tokens (tenant_id, token_hash);
CREATE INDEX IF NOT EXISTS evt_user_idx
    ON email_verification_tokens (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS email_change_tokens (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    old_email       TEXT NOT NULL DEFAULT '',
    new_email       TEXT NOT NULL DEFAULT '',
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL,
    consumed_at_ms  BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS ect_tenant_hash_uidx
    ON email_change_tokens (tenant_id, token_hash);

CREATE TABLE IF NOT EXISTS oauth_identities (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    provider_user_id    TEXT NOT NULL,
    email_at_link_time  TEXT NOT NULL DEFAULT '',
    created_at_ms       BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS oi_tenant_provider_subject_uidx
    ON oauth_identities (tenant_id, provider, provider_user_id);
CREATE INDEX IF NOT EXISTS oi_user_idx
    ON oauth_identities (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS groups (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    created_at_ms   BIGINT NOT NULL,
    updated_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS groups_tenant_name_uidx
    ON groups (tenant_id, name);

CREATE TABLE IF NOT EXISTS group_memberships (
    tenant_id       TEXT NOT NULL,
    group_id        TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at_ms   BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, group_id, user_id)
);
CREATE INDEX IF NOT EXISTS gm_user_idx ON group_memberships (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    actor            TEXT NOT NULL DEFAULT '',
    target           TEXT NOT NULL DEFAULT '',
    ip_address       TEXT NOT NULL DEFAULT '',
    user_agent       TEXT NOT NULL DEFAULT '',
    success          BOOLEAN NOT NULL DEFAULT FALSE,
    details          JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at_ms   BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_actor_time_idx
    ON audit_events (tenant_id, actor, occurred_at_ms DESC);
CREATE INDEX IF NOT EXISTS audit_event_type_idx
    ON audit_events (tenant_id, event_type, occurred_at_ms DESC);

CREATE TABLE IF NOT EXISTS user_invitations (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    email           TEXT NOT NULL,
    user_id         TEXT NOT NULL DEFAULT '',
    invited_by      TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'member'
                       CHECK (role IN ('admin','member','guest')),
    expires_at_ms   BIGINT NOT NULL,
    accepted_at_ms  BIGINT NOT NULL DEFAULT 0,
    created_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS inv_tenant_hash_uidx
    ON user_invitations (tenant_id, token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS inv_tenant_email_uidx
    ON user_invitations (tenant_id, lower(email));

CREATE TABLE IF NOT EXISTS qr_login_sessions (
    id                       TEXT PRIMARY KEY,
    tenant_id                TEXT NOT NULL,
    session_id               TEXT NOT NULL,
    status                   TEXT NOT NULL
                                CHECK (status IN ('pending','approved','rejected','expired','consumed')),
    user_id                  TEXT NOT NULL DEFAULT '',
    new_device_info          TEXT NOT NULL DEFAULT '',
    new_device_ip            TEXT NOT NULL DEFAULT '',
    new_device_user_agent    TEXT NOT NULL DEFAULT '',
    approved_device_info     TEXT NOT NULL DEFAULT '',
    expires_at_ms            BIGINT NOT NULL,
    created_at_ms            BIGINT NOT NULL,
    updated_at_ms            BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS qr_tenant_sid_uidx
    ON qr_login_sessions (tenant_id, session_id);

CREATE TABLE IF NOT EXISTS passkeys (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    credential_id   TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key      TEXT NOT NULL,
    sign_count      BIGINT NOT NULL DEFAULT 0,
    device_name     TEXT NOT NULL DEFAULT '',
    aaguid          TEXT NOT NULL DEFAULT '',
    transports      TEXT NOT NULL DEFAULT '',
    created_at_ms   BIGINT NOT NULL,
    last_used_at_ms BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS passkeys_tenant_credid_uidx
    ON passkeys (tenant_id, credential_id);
CREATE INDEX IF NOT EXISTS passkeys_user_idx
    ON passkeys (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS passkey_challenges (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    challenge        TEXT NOT NULL,
    user_id          TEXT NOT NULL DEFAULT '',
    challenge_type   TEXT NOT NULL
                        CHECK (challenge_type IN ('registration','authentication')),
    expires_at_ms    BIGINT NOT NULL,
    created_at_ms    BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS pkc_tenant_idx ON passkey_challenges (tenant_id);

CREATE TABLE IF NOT EXISTS totp_secrets (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted  TEXT NOT NULL,
    verified          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_ms     BIGINT NOT NULL,
    last_used_at_ms   BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS totp_user_idx ON totp_secrets (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash       TEXT NOT NULL,
    used            BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_ms   BIGINT NOT NULL,
    used_at_ms      BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS rc_tenant_user_code_uidx
    ON recovery_codes (tenant_id, user_id, code_hash);

CREATE TABLE IF NOT EXISTS login_challenges (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    challenge_id    TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS lc_tenant_cid_uidx
    ON login_challenges (tenant_id, challenge_id);
