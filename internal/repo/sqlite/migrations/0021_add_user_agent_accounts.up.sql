-- 0021_add_user_agent_accounts.up.sql
--
-- SQLite mirror of postgres 0038: an agent account's kind, owner and pending
-- transfer. SQLite
-- cannot add a table constraint to an existing table, so the rule that an
-- agent names an owner and a person never does is the column CHECK on
-- owner_user_id below, which may refer to kind; likewise only an agent has a
-- pending transfer.
ALTER TABLE users
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'person' CHECK (kind IN ('person', 'agent'));
ALTER TABLE users
    ADD COLUMN owner_user_id TEXT NOT NULL DEFAULT '' CHECK ((kind = 'agent') = (owner_user_id <> ''));
CREATE INDEX IF NOT EXISTS users_project_owner_idx
    ON users (project_id, owner_user_id)
    WHERE owner_user_id <> '';
ALTER TABLE users
    ADD COLUMN pending_owner_user_id TEXT NOT NULL DEFAULT '' CHECK (pending_owner_user_id = '' OR kind = 'agent');
CREATE INDEX IF NOT EXISTS users_project_pending_owner_idx
    ON users (project_id, pending_owner_user_id)
    WHERE pending_owner_user_id <> '';
