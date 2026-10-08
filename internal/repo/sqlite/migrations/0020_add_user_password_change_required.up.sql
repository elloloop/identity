-- 0020_add_user_password_change_required.up.sql
--
-- SQLite mirror of postgres 0037: set on an account whose password an admin
-- issued, until the person chooses their own.
ALTER TABLE users
    ADD COLUMN password_change_required INTEGER NOT NULL DEFAULT 0;
