-- Self-service account deletion (GDPR Art 17) — sqlite mirror of the postgres
-- migration. Adds deletion_scheduled_at_ms (0 = not pending deletion) and widens
-- the status CHECK to admit 'pending_parental_consent' (age-gating, previously
-- missing from the sqlite CHECK too) and 'pending_deletion'.
--
-- SQLite cannot ALTER a CHECK constraint in place, so the widening requires the
-- official table-rebuild recipe: create the new table, copy, drop, rename,
-- recreate indexes. foreign_keys MUST be disabled for the rebuild so DROP TABLE
-- users does not cascade-delete every child row; because that pragma is a no-op
-- inside a transaction, this driver runs migrations with NoTxWrap and the
-- rebuild carries its own explicit transaction (see migrations.go).
PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE users_new (
    id                       TEXT PRIMARY KEY,
    project_id               TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    email                    TEXT NOT NULL,
    name                     TEXT NOT NULL DEFAULT '',
    role                     TEXT NOT NULL DEFAULT 'member'
                                CHECK (role IN ('admin','member','guest')),
    avatar_url               TEXT NOT NULL DEFAULT '',
    status                   TEXT NOT NULL DEFAULT 'active'
                                CHECK (status IN (
                                    'active','invited','deactivated','suspended',
                                    'pending_parental_consent','pending_deletion'
                                )),
    recovery_email           TEXT NOT NULL DEFAULT '',
    password_hash            TEXT NOT NULL DEFAULT '',
    quota_bytes              INTEGER NOT NULL DEFAULT 0,
    totp_required            INTEGER NOT NULL DEFAULT 0,
    failed_login_count       INTEGER NOT NULL DEFAULT 0,
    locked_until_ms          INTEGER NOT NULL DEFAULT 0,
    email_verified           INTEGER NOT NULL DEFAULT 0,
    email_verified_at_ms     INTEGER NOT NULL DEFAULT 0,
    idv_verified             INTEGER NOT NULL DEFAULT 0,
    idv_verified_at_ms       INTEGER NOT NULL DEFAULT 0,
    phone_number             TEXT NOT NULL DEFAULT '',
    phone_verified           INTEGER NOT NULL DEFAULT 0,
    phone_verified_at_ms     INTEGER NOT NULL DEFAULT 0,
    invited_by               TEXT NOT NULL DEFAULT '',
    invited_at_ms            INTEGER NOT NULL DEFAULT 0,
    last_login_at_ms         INTEGER NOT NULL DEFAULT 0,
    deactivated_at_ms        INTEGER NOT NULL DEFAULT 0,
    created_at_ms            INTEGER NOT NULL,
    updated_at_ms            INTEGER NOT NULL,
    date_of_birth_ms         INTEGER NOT NULL DEFAULT 0,
    external_id              TEXT NOT NULL DEFAULT '',
    deletion_scheduled_at_ms INTEGER NOT NULL DEFAULT 0
);

INSERT INTO users_new (
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
ALTER TABLE users_new RENAME TO users;

CREATE UNIQUE INDEX users_project_email_uidx ON users (project_id, lower(email));
CREATE INDEX users_project_status_idx ON users (project_id, status);
CREATE UNIQUE INDEX users_project_external_id_uidx
    ON users (project_id, external_id)
    WHERE external_id <> '';
CREATE INDEX users_project_created_id_idx
    ON users (project_id, created_at_ms, id);
CREATE INDEX users_project_pending_deletion_idx
    ON users (project_id, deletion_scheduled_at_ms)
    WHERE status = 'pending_deletion';

COMMIT;

PRAGMA foreign_keys=ON;
