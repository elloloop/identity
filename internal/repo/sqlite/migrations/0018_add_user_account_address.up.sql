-- 0018_add_user_account_address.up.sql
--
-- SQLite mirror of postgres 0035: the account address a project issues on its
-- own domain (empty on every account of a project that issues none). The
-- partial unique index covers only non-empty addresses so the default ''
-- rows never collide.
--
-- Own transaction for the same reason as 0015-0017: this driver runs
-- migrations with NoTxWrap, so a failure between the column and its unique
-- index would leave addresses unconstrained.
BEGIN;
ALTER TABLE users
    ADD COLUMN account_address TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX users_project_account_address_uidx
    ON users (project_id, account_address)
    WHERE account_address <> '';
COMMIT;
