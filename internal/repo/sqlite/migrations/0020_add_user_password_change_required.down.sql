-- 0020_add_user_password_change_required.down.sql

ALTER TABLE users DROP COLUMN password_change_required;
