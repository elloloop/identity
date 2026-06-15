-- 0001_init.up.sql (sqlite)
--
-- Squashed final-state schema for the pure-Go SQLite data-plane driver
-- (modernc.org/sqlite — no cgo). This is the SQLite analogue of the
-- postgres driver's migration chain collapsed to its v1.0 shape: every
-- data-plane table carries `project_id` as its leading scoping column
-- (ADR-0002 — the Project is identity's isolation shard) with a FOREIGN
-- KEY to projects(id), and uniqueness is scoped to (project_id, …).
--
-- Dialect differences vs postgres, all behaviour-preserving:
--   * BIGINT/BOOLEAN -> INTEGER (SQLite's native storage class; bools are
--     0/1, matching the service layer's int64-ms and bool fields).
--   * JSONB -> TEXT (SQLite has no JSONB; payloads are stored as JSON text,
--     per the issue's "store JSONB columns as TEXT").
--   * lower(email) expression indexes are kept verbatim — SQLite supports
--     expression indexes, so case-insensitive uniqueness (and the resulting
--     ErrAlreadyExists semantics) matches postgres exactly.
--   * No RLS — that stays postgres-only defense-in-depth. The mandatory
--     `WHERE project_id = $1` repo boundary is the real, backend-agnostic
--     isolation.
--   * FOREIGN KEY ON DELETE CASCADE requires `PRAGMA foreign_keys = ON`,
--     which the driver sets on every pooled connection.
--
-- The control plane (tenants, domains, login policies, governance
-- memberships/invitations, credentials, platform admins) is postgres-only:
-- the SQLite backend targets the embedded / single-project tier. Only the
-- `projects` table is kept here to anchor the project_id FK chain and the
-- EnsureDefaultProject boot seed.

CREATE TABLE projects (
    id                TEXT PRIMARY KEY,
    storage_scope_id  TEXT NOT NULL,
    name              TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active','suspended')),
    config_json       TEXT NOT NULL DEFAULT '{}',
    created_at_ms     INTEGER NOT NULL,
    updated_at_ms     INTEGER NOT NULL
);
CREATE UNIQUE INDEX projects_storage_scope_uidx ON projects (storage_scope_id);
CREATE INDEX projects_status_idx ON projects (status);

CREATE TABLE users (
    id                     TEXT PRIMARY KEY,
    project_id             TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    email                  TEXT NOT NULL,
    name                   TEXT NOT NULL DEFAULT '',
    role                   TEXT NOT NULL DEFAULT 'member'
                              CHECK (role IN ('admin','member','guest')),
    avatar_url             TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active','invited','deactivated','suspended')),
    recovery_email         TEXT NOT NULL DEFAULT '',
    password_hash          TEXT NOT NULL DEFAULT '',
    quota_bytes            INTEGER NOT NULL DEFAULT 0,
    totp_required          INTEGER NOT NULL DEFAULT 0,
    failed_login_count     INTEGER NOT NULL DEFAULT 0,
    locked_until_ms        INTEGER NOT NULL DEFAULT 0,
    email_verified         INTEGER NOT NULL DEFAULT 0,
    email_verified_at_ms   INTEGER NOT NULL DEFAULT 0,
    idv_verified           INTEGER NOT NULL DEFAULT 0,
    idv_verified_at_ms     INTEGER NOT NULL DEFAULT 0,
    phone_number           TEXT NOT NULL DEFAULT '',
    phone_verified         INTEGER NOT NULL DEFAULT 0,
    phone_verified_at_ms   INTEGER NOT NULL DEFAULT 0,
    invited_by             TEXT NOT NULL DEFAULT '',
    invited_at_ms          INTEGER NOT NULL DEFAULT 0,
    last_login_at_ms       INTEGER NOT NULL DEFAULT 0,
    deactivated_at_ms      INTEGER NOT NULL DEFAULT 0,
    created_at_ms          INTEGER NOT NULL,
    updated_at_ms          INTEGER NOT NULL
);
CREATE UNIQUE INDEX users_project_email_uidx ON users (project_id, lower(email));
CREATE INDEX users_project_status_idx ON users (project_id, status);

CREATE TABLE refresh_tokens (
    id                TEXT PRIMARY KEY,
    project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash        TEXT NOT NULL,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_info       TEXT NOT NULL DEFAULT '',
    device_name       TEXT NOT NULL DEFAULT '',
    ip_address        TEXT NOT NULL DEFAULT '',
    user_agent        TEXT NOT NULL DEFAULT '',
    expires_at_ms     INTEGER NOT NULL,
    created_at_ms     INTEGER NOT NULL,
    last_used_at_ms   INTEGER NOT NULL DEFAULT 0,
    consumed_at_ms    INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX refresh_tokens_project_hash_uidx ON refresh_tokens (project_id, token_hash);
CREATE INDEX refresh_tokens_project_user_idx ON refresh_tokens (project_id, user_id);

CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    sid             TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at_ms   INTEGER NOT NULL,
    revoked_at_ms   INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX sessions_project_sid_uidx ON sessions (project_id, sid);
CREATE INDEX sessions_project_user_idx ON sessions (project_id, user_id);

CREATE TABLE password_reset_tokens (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email           TEXT NOT NULL DEFAULT '',
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    consumed_at_ms  INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX prt_project_hash_uidx ON password_reset_tokens (project_id, token_hash);
CREATE INDEX prt_project_user_idx ON password_reset_tokens (project_id, user_id);
CREATE INDEX prt_project_expires_idx ON password_reset_tokens (project_id, expires_at_ms);

CREATE TABLE email_verification_tokens (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    user_id         TEXT NOT NULL DEFAULT '',
    email           TEXT NOT NULL,
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    consumed_at_ms  INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX evt_project_hash_uidx ON email_verification_tokens (project_id, token_hash);
CREATE INDEX evt_project_user_idx ON email_verification_tokens (project_id, user_id);
CREATE INDEX evt_project_expires_idx ON email_verification_tokens (project_id, expires_at_ms);

CREATE TABLE email_change_tokens (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    old_email       TEXT NOT NULL DEFAULT '',
    new_email       TEXT NOT NULL DEFAULT '',
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    consumed_at_ms  INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX ect_project_hash_uidx ON email_change_tokens (project_id, token_hash);
CREATE INDEX ect_project_expires_idx ON email_change_tokens (project_id, expires_at_ms);

CREATE TABLE oauth_identities (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    provider_user_id    TEXT NOT NULL,
    email_at_link_time  TEXT NOT NULL DEFAULT '',
    created_at_ms       INTEGER NOT NULL
);
CREATE UNIQUE INDEX oi_project_provider_subject_uidx ON oauth_identities (project_id, provider, provider_user_id);
CREATE INDEX oi_project_user_idx ON oauth_identities (project_id, user_id);

CREATE TABLE user_invitations (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    email           TEXT NOT NULL,
    user_id         TEXT NOT NULL DEFAULT '',
    invited_by      TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'member'
                       CHECK (role IN ('admin','member','guest')),
    expires_at_ms   INTEGER NOT NULL,
    accepted_at_ms  INTEGER NOT NULL DEFAULT 0,
    created_at_ms   INTEGER NOT NULL
);
CREATE UNIQUE INDEX inv_project_hash_uidx ON user_invitations (project_id, token_hash);
CREATE UNIQUE INDEX inv_project_email_uidx ON user_invitations (project_id, lower(email));
CREATE INDEX inv_project_expires_idx ON user_invitations (project_id, expires_at_ms);

CREATE TABLE qr_login_sessions (
    id                       TEXT PRIMARY KEY,
    project_id               TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    session_id               TEXT NOT NULL,
    status                   TEXT NOT NULL
                                CHECK (status IN ('pending','approved','rejected','expired','consumed')),
    user_id                  TEXT NOT NULL DEFAULT '',
    new_device_info          TEXT NOT NULL DEFAULT '',
    new_device_ip            TEXT NOT NULL DEFAULT '',
    new_device_user_agent    TEXT NOT NULL DEFAULT '',
    approved_device_info     TEXT NOT NULL DEFAULT '',
    poll_secret_hash         TEXT NOT NULL DEFAULT '',
    expires_at_ms            INTEGER NOT NULL,
    created_at_ms            INTEGER NOT NULL,
    updated_at_ms            INTEGER NOT NULL
);
CREATE UNIQUE INDEX qr_project_sid_uidx ON qr_login_sessions (project_id, session_id);
CREATE INDEX qr_project_expires_idx ON qr_login_sessions (project_id, expires_at_ms);

CREATE TABLE passkeys (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    credential_id   TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key      TEXT NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    device_name     TEXT NOT NULL DEFAULT '',
    aaguid          TEXT NOT NULL DEFAULT '',
    transports      TEXT NOT NULL DEFAULT '',
    created_at_ms   INTEGER NOT NULL,
    last_used_at_ms INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX passkeys_project_credid_uidx ON passkeys (project_id, credential_id);
CREATE INDEX passkeys_project_user_idx ON passkeys (project_id, user_id);

CREATE TABLE passkey_challenges (
    id               TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    challenge        TEXT NOT NULL,
    user_id          TEXT NOT NULL DEFAULT '',
    challenge_type   TEXT NOT NULL
                        CHECK (challenge_type IN ('registration','authentication')),
    expires_at_ms    INTEGER NOT NULL,
    created_at_ms    INTEGER NOT NULL
);
CREATE INDEX pkc_project_idx ON passkey_challenges (project_id);
CREATE INDEX pkc_project_expires_idx ON passkey_challenges (project_id, expires_at_ms);

CREATE TABLE totp_secrets (
    id                TEXT PRIMARY KEY,
    project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted  TEXT NOT NULL,
    verified          INTEGER NOT NULL DEFAULT 0,
    created_at_ms     INTEGER NOT NULL,
    last_used_at_ms   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX totp_project_user_idx ON totp_secrets (project_id, user_id);

CREATE TABLE recovery_codes (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash       TEXT NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0,
    created_at_ms   INTEGER NOT NULL,
    used_at_ms      INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX rc_project_user_code_uidx ON recovery_codes (project_id, user_id, code_hash);

CREATE TABLE login_challenges (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    challenge_id    TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL
);
CREATE UNIQUE INDEX lc_project_cid_uidx ON login_challenges (project_id, challenge_id);
CREATE INDEX lc_project_expires_idx ON login_challenges (project_id, expires_at_ms);

CREATE TABLE identity_verifications (
    id                   TEXT PRIMARY KEY,
    project_id           TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    verification_id      TEXT NOT NULL,
    user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider             TEXT NOT NULL,
    provider_session_id  TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL,
    created_at_ms        INTEGER NOT NULL,
    updated_at_ms        INTEGER NOT NULL,
    completed_at_ms      INTEGER NOT NULL DEFAULT 0,
    rejection_reason     TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idv_project_verification_uidx ON identity_verifications (project_id, verification_id);
CREATE INDEX idv_project_user_created_idx ON identity_verifications (project_id, user_id, created_at_ms DESC);

CREATE TABLE oauth_one_time_codes (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    code_hash       TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    consumed_at_ms  INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX oauth_one_time_codes_project_code_uidx ON oauth_one_time_codes (project_id, code_hash);
CREATE INDEX oauth_one_time_codes_project_expires_idx ON oauth_one_time_codes (project_id, expires_at_ms);

CREATE TABLE email_login_codes (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    code_hash       TEXT NOT NULL,
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    consumed_at_ms  INTEGER NOT NULL DEFAULT 0,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX email_login_codes_project_email_uidx ON email_login_codes (project_id, email);
CREATE INDEX email_login_codes_project_expires_idx ON email_login_codes (project_id, expires_at_ms);

CREATE TABLE magic_link_tokens (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    email           TEXT NOT NULL,
    return_to       TEXT NOT NULL DEFAULT '',
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    consumed_at_ms  INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX magic_link_tokens_project_token_uidx ON magic_link_tokens (project_id, token_hash);
CREATE INDEX magic_link_tokens_project_expires_idx ON magic_link_tokens (project_id, expires_at_ms);

CREATE TABLE phone_verification_codes (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    phone_number    TEXT NOT NULL,
    code_hash       TEXT NOT NULL,
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    consumed_at_ms  INTEGER NOT NULL DEFAULT 0,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX phone_verification_codes_project_user_uidx ON phone_verification_codes (project_id, user_id);
CREATE INDEX phone_verification_codes_project_expires_idx ON phone_verification_codes (project_id, expires_at_ms);
