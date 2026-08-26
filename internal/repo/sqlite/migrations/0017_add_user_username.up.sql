-- 0017_add_user_username.up.sql
--
-- SQLite mirror of postgres 0032: the parent-chosen, project-unique username
-- identifying a managed child account (empty on every other account). The
-- partial unique index covers only non-empty usernames so the default ''
-- rows never collide.
--
-- Own transaction for the same reason as 0015/0016: this driver runs
-- migrations with NoTxWrap, so a failure between the column and its unique
-- index would leave usernames unconstrained.
BEGIN;
ALTER TABLE users
    ADD COLUMN username TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX users_project_username_uidx
    ON users (project_id, username)
    WHERE username <> '';
COMMIT;
