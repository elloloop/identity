-- Browser single-sign-on sessions at the auth origin (ADR-0014). Mirrors
-- postgres 0029 — see that migration's comment for what the row means and
-- why project_id is load-bearing (an SSO session in the consumer project
-- must never fast-path a sign-in into an admin project).
--
-- No RLS: sqlite has none, and the driver enforces the same
-- `WHERE project_id = ?` boundary in Go on every statement.

CREATE TABLE sso_sessions (
    id                TEXT PRIMARY KEY,
    project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash        TEXT NOT NULL,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_method      TEXT NOT NULL DEFAULT '',
    ip_address        TEXT NOT NULL DEFAULT '',
    user_agent        TEXT NOT NULL DEFAULT '',
    created_at_ms     INTEGER NOT NULL,
    last_used_at_ms   INTEGER NOT NULL,
    expires_at_ms     INTEGER NOT NULL,
    revoked_at_ms     INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX sso_sessions_project_token_uidx
    ON sso_sessions (project_id, token_hash);
CREATE INDEX sso_sessions_project_user_idx
    ON sso_sessions (project_id, user_id);
CREATE INDEX sso_sessions_project_expires_idx
    ON sso_sessions (project_id, expires_at_ms);
