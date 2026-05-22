-- 0010_add_passwordless_email_login.up.sql
--
-- Passwordless email login (#136): a 6-digit OTP code and a magic link.
-- Both arms prove control of an email and resolve-or-create the single
-- account keyed by that address.
--
-- email_login_codes — the OTP arm.
--   Keyed by email (unique per tenant): a 6-digit code is not globally
--   unique, and brute-force protection must find the active code for an
--   email even when the *guess* is wrong (to bump attempt_count). A new
--   request overwrites the previous code (UpsertEmailLoginCode), so at
--   most one is live per inbox. Single-use is enforced by the consumed_at
--   CAS; attempt_count + max_attempts bound the brute-force window.
--
-- magic_link_tokens — the magic-link arm.
--   Keyed by token_hash (unique, high-entropy). Bound to the requested
--   email and the allowlist-validated return_to. Single-use via the
--   consumed_at CAS, same shape as oauth_one_time_codes.
--
-- Only email/return_to + a short expiry are persisted — no token material
-- (plaintext code / token) is stored at rest.
--
-- Indexes:
--   * (tenant_id, email) unique on email_login_codes — the verify lookup
--     and the upsert target.
--   * (tenant_id, expires_at_ms) on both — the GC sweeper batch delete.
--   * (tenant_id, token_hash) unique on magic_link_tokens — the redeem
--     lookup + CAS target.

CREATE TABLE email_login_codes (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    email           TEXT NOT NULL,
    code_hash       TEXT NOT NULL,
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL,
    consumed_at_ms  BIGINT NOT NULL DEFAULT 0,
    attempt_count   BIGINT NOT NULL DEFAULT 0,
    max_attempts    BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX email_login_codes_tenant_email_uidx
    ON email_login_codes (tenant_id, email);
CREATE INDEX email_login_codes_tenant_expires_idx
    ON email_login_codes (tenant_id, expires_at_ms);

CREATE TABLE magic_link_tokens (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    email           TEXT NOT NULL,
    return_to       TEXT NOT NULL DEFAULT '',
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL,
    consumed_at_ms  BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX magic_link_tokens_tenant_token_uidx
    ON magic_link_tokens (tenant_id, token_hash);
CREATE INDEX magic_link_tokens_tenant_expires_idx
    ON magic_link_tokens (tenant_id, expires_at_ms);
