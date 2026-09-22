-- 0014_add_sso_sessions.up.sql
--
-- Server-side SSO sessions behind the auth origin's cross-product
-- continue-as cookie, mirroring the postgres driver's 0029 migration. One
-- authentication at the auth origin writes a row here (keyed by the
-- SHA-256 hash of the opaque cookie token — the plaintext never touches
-- the database); a product's continue-as request validates the row before
-- minting that product's own one-time code, so token pairs are never
-- shared across products.
--
-- login_method records the ORIGINAL login method so the continue-as gate
-- re-checks the tenant login policy against the method the session was
-- actually established with. Revocation is hard deletion; expiry is
-- reaped by the GC sweeper; user_id cascades with the account.
CREATE TABLE sso_sessions (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_method    TEXT NOT NULL,
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL
);
CREATE UNIQUE INDEX sso_sessions_project_token_uidx
    ON sso_sessions (project_id, token_hash);
CREATE INDEX sso_sessions_project_user_idx
    ON sso_sessions (project_id, user_id);
CREATE INDEX sso_sessions_project_expires_idx
    ON sso_sessions (project_id, expires_at_ms);
