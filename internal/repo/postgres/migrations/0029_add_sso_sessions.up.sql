-- 0029_add_sso_sessions.up.sql
--
-- Server-side SSO sessions behind the auth origin's cross-product
-- continue-as cookie. One authentication at the auth origin writes a row
-- here (keyed by the SHA-256 hash of the opaque cookie token — the
-- plaintext never touches the database); a product's continue-as request
-- validates the row before minting that product's own one-time code, so
-- token pairs are never shared across products.
--
-- login_method records the ORIGINAL login method (e.g. "oauth") so the
-- continue-as gate re-checks the tenant login policy against the method
-- the session was actually established with — a cookie cannot launder a
-- login a tightened policy would now refuse.
--
-- Revocation is hard deletion (RevokeSSOSessionsForUser fires from every
-- credential-kill path and from SignOutEverywhere); expiry is reaped by
-- the GC sweeper. project_id carries the FOREIGN KEY to projects(id) ON
-- DELETE CASCADE every data-plane table has (migration 0015); user_id
-- cascades with the account so DeleteUser drains sessions with it.
--
-- Indexes:
--   * (project_id, token_hash) unique — the continue-as lookup target.
--   * (project_id, user_id) — the per-user revoke/delete fan-out.
--   * (project_id, expires_at_ms) — for the GC sweeper batch delete.

CREATE TABLE sso_sessions (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_method    TEXT NOT NULL,
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX sso_sessions_project_token_uidx
    ON sso_sessions (project_id, token_hash);
CREATE INDEX sso_sessions_project_user_idx
    ON sso_sessions (project_id, user_id);
CREATE INDEX sso_sessions_project_expires_idx
    ON sso_sessions (project_id, expires_at_ms);

-- Row-level security: pin every row to the request's project, matching the
-- data-plane isolation posture migration 0016 established for the other
-- ephemeral-auth tables.
ALTER TABLE sso_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sso_sessions_project_isolation ON sso_sessions
    USING (project_id = current_setting('app.current_project_id', true));
