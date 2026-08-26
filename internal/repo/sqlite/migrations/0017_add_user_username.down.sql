-- 0017_add_user_username.down.sql

DROP INDEX IF EXISTS users_project_username_idx;
ALTER TABLE users DROP COLUMN username;
