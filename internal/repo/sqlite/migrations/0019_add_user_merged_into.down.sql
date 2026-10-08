-- 0019_add_user_merged_into.down.sql

ALTER TABLE users DROP COLUMN merged_into_user_id;
