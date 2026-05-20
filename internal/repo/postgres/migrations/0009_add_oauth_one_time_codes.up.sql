-- 0009_add_oauth_one_time_codes.up.sql
--
-- One-time codes for the hosted OAuth flow (see docs/oauth.md and the
-- docs/IDENTITY.md decision log entry for #126).
--
-- The hosted callback (GET /oauth/callback/{provider}) completes the
-- code exchange, authenticates the user, then mints an opaque code,
-- stores its SHA-256 hash here, and 302-redirects the browser to
-- return_to?code=<otc>. The SPA exchanges the code via the
-- RedeemOAuthCode RPC, which atomically consumes this row and mints a
-- fresh token pair.
--
-- Only the user id + a short expiry are persisted — no token material
-- is stored at rest. Single-use is enforced by ConsumeOAuthOneTimeCode
-- via a CAS UPDATE gated on consumed_at_ms = 0.
--
-- Indexes:
--   * (tenant_id, code_hash) unique — the redeem lookup + CAS target.
--   * (tenant_id, expires_at_ms) — for the GC sweeper batch delete.

CREATE TABLE oauth_one_time_codes (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    code_hash       TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL,
    consumed_at_ms  BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX oauth_one_time_codes_tenant_code_uidx
    ON oauth_one_time_codes (tenant_id, code_hash);
CREATE INDEX oauth_one_time_codes_tenant_expires_idx
    ON oauth_one_time_codes (tenant_id, expires_at_ms);
