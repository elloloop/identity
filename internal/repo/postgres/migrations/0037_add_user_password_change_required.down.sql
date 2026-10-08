-- 0037_add_user_password_change_required.down.sql
--
-- Dropping the column lifts every pending required change: temporary
-- passwords then sign in as ordinary ones.

ALTER TABLE users
    DROP COLUMN IF EXISTS password_change_required;
