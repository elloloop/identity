-- 0028_add_recovery_emails.down.sql
ALTER TABLE login_challenges DROP COLUMN recovery_email_id;
ALTER TABLE refresh_tokens DROP COLUMN recovery_email_id;
DROP TABLE recovery_email_codes;
DROP TABLE user_recovery_emails;
