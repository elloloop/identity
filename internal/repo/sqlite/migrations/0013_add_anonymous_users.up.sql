-- Anonymous identity (ADR-0013). Mirrors postgres 0028: an anonymous user is
-- a real user row holding no credential (no email, no password, no provider
-- identity), reachable only through its refresh token and keeping its id
-- across an upgrade to a permanent account.
ALTER TABLE users ADD COLUMN is_anonymous BOOLEAN NOT NULL DEFAULT 0;

-- Email uniqueness applies only to users that HAVE an email; anonymous users
-- all carry '' and must coexist within a project.
CREATE UNIQUE INDEX IF NOT EXISTS users_project_email_partial_uidx
    ON users (project_id, lower(email))
    WHERE email <> '';
DROP INDEX IF EXISTS users_project_email_uidx;

-- Backing index for the anonymous-retention sweep.
CREATE INDEX IF NOT EXISTS users_project_anonymous_last_login_idx
    ON users (project_id, last_login_at_ms)
    WHERE is_anonymous;
