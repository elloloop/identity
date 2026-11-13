-- 0059_add_recovery_emails.down.sql
--
-- Drops recovery emails and their pending codes. Every address an account
-- proved is lost; primary emails are untouched. Sessions forget whether a
-- recovery email opened them, and a sign-in waiting on its second factor
-- forgets that a recovery email made it.
SET LOCAL lock_timeout = '10s';

ALTER TABLE login_challenges DROP COLUMN recovery_email;
ALTER TABLE refresh_tokens DROP COLUMN amr;

DROP TABLE recovery_email_codes;
DROP TABLE user_recovery_emails;
