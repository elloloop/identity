-- 0043_add_oauth_one_time_code_challenge.up.sql
--
-- The S256 PKCE challenge an app sent to GET /oauth/start, bound to the
-- one-time code the hosted callback mints for that sign-in. RedeemOAuthCode
-- consumes the code only when the S256 of the presented code_verifier equals
-- it; empty means the app sent no challenge, and such a code is redeemed
-- without a verifier, as before.
-- A constant default makes this a catalog-only change; lock_timeout bounds the
-- wait for the lock as in 0034-0037 (on timeout: confirm the column is absent,
-- then `identity migrate force 42` and `identity migrate`).
SET LOCAL lock_timeout = '10s';

ALTER TABLE oauth_one_time_codes
    ADD COLUMN IF NOT EXISTS code_challenge TEXT NOT NULL DEFAULT '';
