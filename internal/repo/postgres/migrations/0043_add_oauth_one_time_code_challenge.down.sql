-- 0043_add_oauth_one_time_code_challenge.down.sql
--
-- Dropping the column unbinds every outstanding one-time code from its
-- challenge: for the rest of their 60 seconds they redeem without a verifier.

ALTER TABLE oauth_one_time_codes
    DROP COLUMN IF EXISTS code_challenge;
