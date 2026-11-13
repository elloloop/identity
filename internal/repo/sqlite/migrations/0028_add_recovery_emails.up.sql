-- 0028_add_recovery_emails.up.sql
--
-- Recovery emails: additional addresses an account has proved it controls.
-- user_recovery_emails holds one row per proved address, unique per project
-- under the same ASCII fold as users.email, with when it last signed in to
-- its account and when the latest hold it started began (0 = never), from
-- which a hold on the account's security settings is measured;
-- recovery_email_codes is the emailed code that proves an address before a
-- row is stored, at most one live code per user.
CREATE TABLE user_recovery_emails (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email          TEXT NOT NULL CHECK (email <> ''),
    verified_at_ms INTEGER NOT NULL,
    last_sign_in_at_ms INTEGER NOT NULL DEFAULT 0,
    hold_started_at_ms INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX user_recovery_emails_project_email_uidx ON user_recovery_emails (project_id, lower(email));
CREATE INDEX user_recovery_emails_project_user_idx ON user_recovery_emails (project_id, user_id, verified_at_ms, id);

CREATE TABLE recovery_email_codes (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    code_hash       TEXT NOT NULL,
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    consumed_at_ms  INTEGER NOT NULL DEFAULT 0,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX recovery_email_codes_project_user_uidx ON recovery_email_codes (project_id, user_id);
CREATE INDEX recovery_email_codes_project_expires_idx ON recovery_email_codes (project_id, expires_at_ms);

-- The user_recovery_emails.id of the recovery email whose sign-in opened a
-- session ('' for a session opened any other way), whose removal ends it,
-- and of the recovery email a sign-in waiting on its second factor was made
-- with.
ALTER TABLE refresh_tokens ADD COLUMN recovery_email_id TEXT NOT NULL DEFAULT '';
ALTER TABLE login_challenges ADD COLUMN recovery_email_id TEXT NOT NULL DEFAULT '';
