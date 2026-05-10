ALTER TABLE users
    DROP COLUMN IF EXISTS idv_verified_at_ms,
    DROP COLUMN IF EXISTS idv_verified;
