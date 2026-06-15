-- 0001_init.down.sql (sqlite)
--
-- Drops every table created by the up migration. Order is leaf-to-root
-- so the project_id / user_id FOREIGN KEY chains do not block the drop
-- when foreign_keys = ON.

DROP TABLE IF EXISTS phone_verification_codes;
DROP TABLE IF EXISTS magic_link_tokens;
DROP TABLE IF EXISTS email_login_codes;
DROP TABLE IF EXISTS oauth_one_time_codes;
DROP TABLE IF EXISTS identity_verifications;
DROP TABLE IF EXISTS login_challenges;
DROP TABLE IF EXISTS recovery_codes;
DROP TABLE IF EXISTS totp_secrets;
DROP TABLE IF EXISTS passkey_challenges;
DROP TABLE IF EXISTS passkeys;
DROP TABLE IF EXISTS qr_login_sessions;
DROP TABLE IF EXISTS user_invitations;
DROP TABLE IF EXISTS oauth_identities;
DROP TABLE IF EXISTS email_change_tokens;
DROP TABLE IF EXISTS email_verification_tokens;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS projects;
