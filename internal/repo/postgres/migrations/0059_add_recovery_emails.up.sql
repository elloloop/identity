-- 0059_add_recovery_emails.up.sql
--
-- Recovery emails: additional addresses an account has proved it controls.
--
-- user_recovery_emails holds one row per proved address. email_fold is the
-- key users.email_fold is (0034), and (project_id, email_fold) is unique, so
-- an address is one account's recovery email at most. That it is no
-- account's primary email is the writers' rule: every write of users.email
-- and every insert here takes the same per-address advisory lock and checks
-- the other table inside it.
--
-- last_sign_in_at_ms is when the address last signed in to its account (0 =
-- never). A sign-in by a recovery email starts a hold on the account's
-- recovery settings, measured from the latest of these, so the hold needs no
-- column of its own and follows the project's configured length.
--
-- recovery_email_codes is the emailed code that proves an address before a
-- row is stored: at most one live code per user, as phone_verification_codes.
--
-- Both tables are new and empty, so nothing here waits on or rewrites
-- existing rows.
SET LOCAL lock_timeout = '10s';

CREATE TABLE user_recovery_emails (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email          TEXT NOT NULL CHECK (email <> ''),
    email_fold     TEXT COLLATE "C" GENERATED ALWAYS AS (lower(email COLLATE "C")) STORED,
    verified_at_ms BIGINT NOT NULL,
    last_sign_in_at_ms BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX user_recovery_emails_project_email_fold_uidx
    ON user_recovery_emails (project_id, email_fold);
CREATE INDEX user_recovery_emails_project_user_idx
    ON user_recovery_emails (project_id, user_id, verified_at_ms, id);
ALTER TABLE user_recovery_emails ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_recovery_emails FORCE ROW LEVEL SECURITY;
CREATE POLICY user_recovery_emails_project_isolation ON user_recovery_emails
    USING (project_id = current_setting('app.current_project_id', true));

CREATE TABLE recovery_email_codes (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    code_hash       TEXT NOT NULL,
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL,
    consumed_at_ms  BIGINT NOT NULL DEFAULT 0,
    attempt_count   BIGINT NOT NULL DEFAULT 0,
    max_attempts    BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX recovery_email_codes_project_user_uidx
    ON recovery_email_codes (project_id, user_id);
CREATE INDEX recovery_email_codes_project_expires_idx
    ON recovery_email_codes (project_id, expires_at_ms);
ALTER TABLE recovery_email_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_email_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_email_codes_project_isolation ON recovery_email_codes
    USING (project_id = current_setting('app.current_project_id', true));
