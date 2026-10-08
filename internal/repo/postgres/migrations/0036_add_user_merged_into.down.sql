-- 0036_add_user_merged_into.down.sql
--
-- Dropping the column drops every merge link: retired accounts become
-- ordinary deactivated accounts that an admin can reactivate again.

ALTER TABLE users
    DROP COLUMN IF EXISTS merged_into_user_id;
