-- Reverse the rebuild: restore the pre-0009 users table (original status CHECK,
-- no deletion_scheduled_at_ms). Any pending_deletion / pending_parental_consent
-- rows would violate the narrower CHECK; a deployment rolling back must resolve
-- those first. Same NoTxWrap + explicit-transaction contract as the up.
PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE users_old (
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
    updated_at_ms          INTEGER NOT NULL,
    date_of_birth_ms       INTEGER NOT NULL DEFAULT 0,
    external_id            TEXT NOT NULL DEFAULT ''
);

INSERT INTO users_old (
    id, project_id, email, name, role, avatar_url, status, recovery_email,
    password_hash, quota_bytes, totp_required, failed_login_count, locked_until_ms,
    email_verified, email_verified_at_ms, idv_verified, idv_verified_at_ms,
    phone_number, phone_verified, phone_verified_at_ms, invited_by, invited_at_ms,
    last_login_at_ms, deactivated_at_ms, created_at_ms, updated_at_ms,
    date_of_birth_ms, external_id
)
SELECT
    id, project_id, email, name, role, avatar_url, status, recovery_email,
    password_hash, quota_bytes, totp_required, failed_login_count, locked_until_ms,
    email_verified, email_verified_at_ms, idv_verified, idv_verified_at_ms,
    phone_number, phone_verified, phone_verified_at_ms, invited_by, invited_at_ms,
    last_login_at_ms, deactivated_at_ms, created_at_ms, updated_at_ms,
    date_of_birth_ms, external_id
FROM users;

DROP TABLE users;
ALTER TABLE users_old RENAME TO users;

CREATE UNIQUE INDEX users_project_email_uidx ON users (project_id, lower(email));
CREATE INDEX users_project_status_idx ON users (project_id, status);
CREATE UNIQUE INDEX users_project_external_id_uidx
    ON users (project_id, external_id)
    WHERE external_id <> '';
CREATE INDEX users_project_created_id_idx
    ON users (project_id, created_at_ms, id);

COMMIT;

PRAGMA foreign_keys=ON;
