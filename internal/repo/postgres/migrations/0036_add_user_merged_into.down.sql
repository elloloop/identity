-- 0036_add_user_merged_into.down.sql

ALTER TABLE users
    DROP COLUMN IF EXISTS merged_into_user_id;
