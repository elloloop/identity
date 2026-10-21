-- 0043_add_oauth_one_time_code_challenge.down.sql
--
-- Dropping the column unbinds every outstanding one-time code from its
-- challenge: for the rest of their 60 seconds they redeem without a verifier.
-- lock_timeout bounds the wait for the lock, as the up migration does.
SET LOCAL lock_timeout = '10s';

ALTER TABLE oauth_one_time_codes
    DROP COLUMN IF EXISTS code_challenge;
