-- 0038_add_user_agent_accounts.up.sql
--
-- Agent accounts: a non-human account a person owns. kind is 'agent' on one
-- and 'person' on every other account; owner_user_id names an agent's owner
-- and is empty on a person. owner_user_id carries no foreign key on purpose:
-- deleting the owner leaves the agent naming it, unusable until an admin
-- transfers it, rather than deleting the agent with its owner.
--
-- Constant defaults make the two ADD COLUMNs catalog-only changes (no table
-- rewrite). The CHECK constraints are added NOT VALID, which skips the scan of
-- existing rows: every one of them takes the defaults ('person', ''), which
-- satisfy both, and every later write is checked. The ALTERs take an ACCESS
-- EXCLUSIVE lock that the transaction holds to commit, so reads as well as
-- writes wait for the rest of the file, including the owner index's build:
-- one scan of `users` that indexes nothing, the index being partial.
-- lock_timeout bounds the wait to acquire the lock, as in 0034-0037: on timeout the file rolls back and version 38 is left
-- dirty — confirm kind is absent, then `identity migrate force 37` and
-- `identity migrate` again. The IF [NOT] EXISTS guards let an operator
-- pre-build the index with CREATE INDEX CONCURRENTLY.
SET LOCAL lock_timeout = '10s';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'person',
    ADD COLUMN IF NOT EXISTS owner_user_id TEXT NOT NULL DEFAULT '';

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_kind_check;
ALTER TABLE users
    ADD CONSTRAINT users_kind_check CHECK (kind IN ('person', 'agent')) NOT VALID;

-- An agent always names an owner and a person never does.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_agent_owner_check;
ALTER TABLE users
    ADD CONSTRAINT users_agent_owner_check CHECK ((kind = 'agent') = (owner_user_id <> '')) NOT VALID;

CREATE INDEX IF NOT EXISTS users_project_owner_idx
    ON users (project_id, owner_user_id)
    WHERE owner_user_id <> '';
