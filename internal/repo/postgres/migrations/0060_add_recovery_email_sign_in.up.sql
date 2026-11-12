-- 0060_add_recovery_email_sign_in.up.sql
--
-- user_recovery_emails gains when the address last signed in to its account.
-- A sign-in by a recovery email starts a hold on the account's recovery
-- settings, measured from the latest of these, so the hold needs no column of
-- its own and follows the project's configured length. 0 means the address
-- has never signed in. Adding a column with a constant default rewrites
-- nothing.
SET LOCAL lock_timeout = '10s';

ALTER TABLE user_recovery_emails ADD COLUMN last_sign_in_at_ms BIGINT NOT NULL DEFAULT 0;
