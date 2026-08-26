-- 0017_add_user_username.up.sql
--
-- SQLite mirror of postgres 0032: the parent-chosen, project-unique username
-- identifying a managed child account (empty on every other account). The
-- partial unique index covers only non-empty usernames so the default ''
-- rows never collide.
ALTER TABLE users
    ADD COLUMN username TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX users_project_username_idx
    ON users (project_id, username)
    WHERE username <> '';
