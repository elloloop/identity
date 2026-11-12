-- 0059_add_recovery_emails.down.sql
--
-- Drops recovery emails and their pending codes. Every address an account
-- proved is lost; primary emails are untouched.
SET LOCAL lock_timeout = '10s';

DROP TABLE recovery_email_codes;
DROP TABLE user_recovery_emails;
