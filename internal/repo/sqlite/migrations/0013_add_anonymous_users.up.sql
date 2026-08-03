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

-- The anonymous activity clock gets its own column; see the postgres 0028
-- comment — indexing last_login_at_ms would defeat HOT updates for every
-- ordinary login's last-login stamp.
ALTER TABLE users ADD COLUMN anonymous_last_seen_ms BIGINT NOT NULL DEFAULT 0;

-- Backing index for the anonymous-retention sweep.
CREATE INDEX IF NOT EXISTS users_project_anonymous_last_seen_idx
    ON users (project_id, anonymous_last_seen_ms)
    WHERE is_anonymous;

-- Backing index for the complement of the sweep predicate. userFilterWhere
-- appends `NOT is_anonymous` to every ListUsers/CountUsers query, and SCIM
-- calls CountUsers on every /Users list request to fill totalResults — so
-- without this the predicate turns an index-only scan into a sequential scan
-- of the project's users, and the added filter makes the planner abandon the
-- ordered index for deep pages. Partial on the complement so it carries no
-- anonymous rows, which makes it smaller than the total index it replaces
-- for this access path.
CREATE INDEX IF NOT EXISTS users_project_created_id_nonanon_idx
    ON users (project_id, created_at_ms, id)
    WHERE NOT is_anonymous;
