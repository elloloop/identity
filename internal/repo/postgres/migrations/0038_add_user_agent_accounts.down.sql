-- 0038_add_user_agent_accounts.down.sql
--
-- Dropping the columns turns every agent into an ordinary account with no
-- sign-in method: delete agents first (DeleteAgent) if they must not remain.

DROP INDEX IF EXISTS users_project_pending_owner_idx;
DROP INDEX IF EXISTS users_project_owner_idx;
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_agent_pending_owner_check,
    DROP CONSTRAINT IF EXISTS users_agent_owner_check,
    DROP CONSTRAINT IF EXISTS users_kind_check,
    DROP COLUMN IF EXISTS pending_owner_user_id,
    DROP COLUMN IF EXISTS owner_user_id,
    DROP COLUMN IF EXISTS kind;
