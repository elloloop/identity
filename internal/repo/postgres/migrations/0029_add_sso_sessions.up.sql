-- 0029_add_sso_sessions.up.sql
--
-- Browser single-sign-on sessions at the auth origin (ADR-0014).
--
-- A row records that ONE BROWSER completed an authentication, so a second
-- product asking for a session can be served without repeating the provider
-- round trip. It is not a credential for any product: no token material is
-- stored, the row is never sent to a product origin, and the fast path
-- re-runs the account/access/policy checks a cold sign-in runs before
-- anything is minted. What the browser holds is an opaque random value in a
-- host-locked `__Host-sso_session` cookie; only its SHA-256 lands here, the
-- same posture refresh_tokens and oauth_one_time_codes take.
--
-- login_method records HOW the session was established (password, oauth,
-- passkey…) so the fast path can replay the tenant's login policy against
-- the real method instead of a synthetic "sso" one — a cookie must not
-- launder a weak login into a stronger one.
--
-- expires_at_ms is ROLLING: re-anchored at now + TTL on each use, so an
-- active browser stays signed in and an abandoned one lapses on schedule.
-- revoked_at_ms is what "sign out everywhere" sets.
--
-- project_id carries the same FOREIGN KEY every data-plane table has since
-- 0015. It is load-bearing for more than storage hygiene here: an SSO
-- session established in the default (consumer) project must never fast-path
-- a sign-in into a separate admin project, and scoping the lookup by
-- project_id is what makes that structural rather than a check someone can
-- forget.
--
-- Indexes:
--   * (project_id, token_hash) unique — the cookie lookup, and the guarantee
--     that one cookie value maps to at most one session.
--   * (project_id, user_id) — "sign out everywhere" and the delete cascade.
--   * (project_id, expires_at_ms) — the GC sweeper batch delete.

CREATE TABLE sso_sessions (
    id                TEXT PRIMARY KEY,
    project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash        TEXT NOT NULL,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_method      TEXT NOT NULL DEFAULT '',
    ip_address        TEXT NOT NULL DEFAULT '',
    user_agent        TEXT NOT NULL DEFAULT '',
    created_at_ms     BIGINT NOT NULL,
    last_used_at_ms   BIGINT NOT NULL,
    expires_at_ms     BIGINT NOT NULL,
    revoked_at_ms     BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX sso_sessions_project_token_uidx
    ON sso_sessions (project_id, token_hash);
CREATE INDEX sso_sessions_project_user_idx
    ON sso_sessions (project_id, user_id);
CREATE INDEX sso_sessions_project_expires_idx
    ON sso_sessions (project_id, expires_at_ms);

-- Row-level security: pin every row to the request's project, matching the
-- data-plane isolation posture migration 0016 established.
ALTER TABLE sso_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sso_sessions_project_isolation ON sso_sessions
    USING (project_id = current_setting('app.current_project_id', true));
