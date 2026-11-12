-- 0029_add_recovery_email_sign_in.down.sql
ALTER TABLE user_recovery_emails DROP COLUMN last_sign_in_at_ms;
