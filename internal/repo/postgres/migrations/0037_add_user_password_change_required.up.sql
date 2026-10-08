-- 0037_add_user_password_change_required.up.sql
--
-- Set on an account whose password an admin issued (a temporary password):
-- PasswordLogin then refuses a session until the person chooses their own
-- password (CompleteRequiredPasswordChange). Cleared by every password change.
-- A constant default makes this a catalog-only change; lock_timeout bounds the
-- wait for the lock as in 0034-0036 (on timeout: confirm the column is absent,
-- then `identity migrate force 36` and `identity migrate`).
SET LOCAL lock_timeout = '10s';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_change_required BOOLEAN NOT NULL DEFAULT FALSE;
