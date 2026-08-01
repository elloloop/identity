-- Anonymous users cannot be represented in the pre-0028 schema: they share
-- the empty email that the total unique index forbids more than one of. They
-- are deleted rather than left to fail the index rebuild half-way, which is
-- also the honest outcome — an anonymous account carries no credential, so
-- there is nothing for its owner to sign back in with once the feature is
-- rolled back. Their child rows go with them via ON DELETE CASCADE.
DELETE FROM users WHERE is_anonymous;

DROP INDEX IF EXISTS users_project_anonymous_last_login_idx;
CREATE UNIQUE INDEX IF NOT EXISTS users_project_email_uidx
    ON users (project_id, lower(email));
DROP INDEX IF EXISTS users_project_email_partial_uidx;

ALTER TABLE users DROP COLUMN IF EXISTS is_anonymous;
