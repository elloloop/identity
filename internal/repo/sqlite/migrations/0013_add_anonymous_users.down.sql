-- See postgres 0028 down: anonymous users share the empty email that the
-- restored total unique index forbids more than one of, and hold no
-- credential to sign back in with, so they are deleted rather than left to
-- break the index rebuild.
DELETE FROM users WHERE is_anonymous;

DROP INDEX IF EXISTS users_project_anonymous_last_login_idx;
CREATE UNIQUE INDEX IF NOT EXISTS users_project_email_uidx
    ON users (project_id, lower(email));
DROP INDEX IF EXISTS users_project_email_partial_uidx;

ALTER TABLE users DROP COLUMN is_anonymous;
