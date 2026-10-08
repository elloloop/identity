-- 0036_add_user_merged_into.up.sql
--
-- The account a merged account was merged into. A merged account has status
-- 'deactivated' with merged_into_user_id naming the survivor; it is retired,
-- never deleted: its rows stay for the survivor's
-- application to move. Empty on every unmerged account. A constant default
-- makes this a catalog-only change; lock_timeout bounds the wait for the
-- lock as in 0034/0035 (on timeout: confirm the column is absent, then
-- `identity migrate force 35` and `identity migrate`).
SET LOCAL lock_timeout = '10s';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS merged_into_user_id TEXT NOT NULL DEFAULT '';
