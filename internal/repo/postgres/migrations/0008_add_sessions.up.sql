-- 0008_add_sessions.up.sql
--
-- Sessions table for `GATEWAY_REVOCATION_MODE=session` deployments
-- (see docs/IDENTITY.md decision log §6).
--
-- One row per logged-in session; access tokens minted under
-- mode=session carry an `sid` claim referencing sessions.sid. The
-- verification middleware reads the row (via an in-process cache)
-- and rejects requests when `revoked_at_ms != 0`.
--
-- Indexes:
--   * (tenant_id, sid) unique — the hot-path lookup by sid claim.
--   * (tenant_id, user_id) — for RevokeSessionsForUser (called from
--     DeleteRefreshTokensForUser so the existing replay-detection
--     path also kills the access tokens).
--
-- In mode=ttl (the default) this table is never written or read;
-- the indexes pay zero cost for deployers who never opt in.

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    sid             TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at_ms   BIGINT NOT NULL,
    revoked_at_ms   BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS sessions_tenant_sid_uidx
    ON sessions (tenant_id, sid);
CREATE INDEX IF NOT EXISTS sessions_tenant_user_idx
    ON sessions (tenant_id, user_id);
