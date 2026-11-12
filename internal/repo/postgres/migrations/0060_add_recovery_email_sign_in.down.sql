-- 0060_add_recovery_email_sign_in.down.sql
--
-- Drops when each recovery email last signed in, which ends every hold in
-- force.
SET LOCAL lock_timeout = '10s';

ALTER TABLE user_recovery_emails DROP COLUMN last_sign_in_at_ms;
