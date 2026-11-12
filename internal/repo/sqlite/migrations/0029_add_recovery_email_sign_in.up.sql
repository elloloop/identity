-- 0029_add_recovery_email_sign_in.up.sql
--
-- user_recovery_emails gains when the address last signed in to its account;
-- 0 means never. A hold on the account's recovery settings is measured from
-- the latest of these.
ALTER TABLE user_recovery_emails ADD COLUMN last_sign_in_at_ms INTEGER NOT NULL DEFAULT 0;
