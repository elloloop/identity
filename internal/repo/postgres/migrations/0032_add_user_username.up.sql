-- 0032_add_user_username.up.sql
--
-- Managed child accounts (#460): the parent-chosen, project-unique username
-- identifying a managed child account (children often have no email). Empty
-- on every account not created via CreateManagedChildAccount. The partial
-- unique index covers only non-empty usernames (matching the email index's
-- posture), so the default '' rows never collide.
ALTER TABLE users
    ADD COLUMN username TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX users_project_username_idx
    ON users (project_id, username)
    WHERE username <> '';
