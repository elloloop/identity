-- 0019_add_user_merged_into.up.sql
--
-- SQLite mirror of postgres 0036: the account a merged account was merged
-- into. Empty on every unmerged account.
ALTER TABLE users
    ADD COLUMN merged_into_user_id TEXT NOT NULL DEFAULT '';
