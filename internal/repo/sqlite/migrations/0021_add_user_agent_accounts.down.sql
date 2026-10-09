-- 0021_add_user_agent_accounts.down.sql
--
-- Dropping the columns turns every agent into an ordinary account with no
-- sign-in method: delete agents first (DeleteAgent) if they must not remain.

DROP INDEX IF EXISTS users_project_owner_idx;
ALTER TABLE users DROP COLUMN owner_user_id;
ALTER TABLE users DROP COLUMN kind;
