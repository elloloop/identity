-- 0011_add_phone_verification.down.sql

DROP INDEX IF EXISTS phone_verification_codes_tenant_expires_idx;
DROP INDEX IF EXISTS phone_verification_codes_tenant_user_uidx;
DROP TABLE IF EXISTS phone_verification_codes;

ALTER TABLE users
    DROP COLUMN IF EXISTS phone_verified_at_ms,
    DROP COLUMN IF EXISTS phone_verified,
    DROP COLUMN IF EXISTS phone_number;
