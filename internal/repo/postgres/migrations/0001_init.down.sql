-- 0001_init.down.sql
-- Reverse of 0001_init.up.sql. Drop in reverse FK order so the cascade
-- relationships do not bite us in case ON DELETE CASCADE is changed
-- later.

DROP TABLE IF EXISTS login_challenges;
DROP TABLE IF EXISTS recovery_codes;
DROP TABLE IF EXISTS totp_secrets;
DROP TABLE IF EXISTS passkey_challenges;
DROP TABLE IF EXISTS passkeys;
DROP TABLE IF EXISTS qr_login_sessions;
DROP TABLE IF EXISTS user_invitations;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS group_memberships;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS oauth_identities;
DROP TABLE IF EXISTS email_change_tokens;
DROP TABLE IF EXISTS email_verification_tokens;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;
