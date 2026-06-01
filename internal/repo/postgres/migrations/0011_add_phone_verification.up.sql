-- 0011_add_phone_verification.up.sql
--
-- SMS-OTP phone-ownership verification for an already-authenticated user
-- (not yet a login factor). Adds the verified-phone columns to users and
-- the phone_verification_codes table — the SMS analogue of
-- email_login_codes, but keyed by user_id (the caller is a known
-- account) so DeleteUser can cascade it.
--
-- users columns:
--   phone_number          E.164 number the user has verified ownership of
--   phone_verified        true once an SMS OTP for that number was confirmed
--   phone_verified_at_ms  epoch ms; 0 = never verified
--
-- phone_verification_codes:
--   Keyed by (tenant_id, user_id) unique — at most one live code per user;
--   a re-request overwrites the previous one (UpsertPhoneVerificationCode).
--   Single-use via the consumed_at_ms CAS; attempt_count + max_attempts
--   bound the brute-force window. FK ON DELETE CASCADE to users so the
--   user delete drains it automatically.
--
-- Indexes:
--   * (tenant_id, user_id) unique — the verify lookup and upsert target.
--   * (tenant_id, expires_at_ms) — the GC sweeper batch delete.

ALTER TABLE users
    ADD COLUMN phone_number         TEXT   NOT NULL DEFAULT '',
    ADD COLUMN phone_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN phone_verified_at_ms BIGINT NOT NULL DEFAULT 0;

CREATE TABLE phone_verification_codes (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    phone_number    TEXT NOT NULL,
    code_hash       TEXT NOT NULL,
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL,
    consumed_at_ms  BIGINT NOT NULL DEFAULT 0,
    attempt_count   BIGINT NOT NULL DEFAULT 0,
    max_attempts    BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX phone_verification_codes_tenant_user_uidx
    ON phone_verification_codes (tenant_id, user_id);
CREATE INDEX phone_verification_codes_tenant_expires_idx
    ON phone_verification_codes (tenant_id, expires_at_ms);
