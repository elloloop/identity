-- 0028_add_recovery_emails.down.sql
ALTER TABLE login_challenges DROP COLUMN recovery_email;
ALTER TABLE refresh_tokens DROP COLUMN amr;
DROP TABLE recovery_email_codes;
DROP TABLE user_recovery_emails;
