-- Anonymous users cannot be represented in the pre-0028 schema: they share
-- the empty email that the total unique index forbids more than one of. They
-- are deleted rather than left to fail the index rebuild half-way, which is
-- also the honest outcome — an anonymous account carries no credential, so
-- there is nothing for its owner to sign back in with once the feature is
-- rolled back. Their child rows go with them via ON DELETE CASCADE.
--
-- RLS must be suspended for that delete. 0016 put ENABLE + FORCE ROW LEVEL
-- SECURITY on `users` with a policy keyed on
-- current_setting('app.current_project_id'), and the migration runner opens
-- its own connection that never sets that GUC. Under a non-superuser role
-- the policy therefore fails closed and the DELETE matches NOTHING —
-- verified on postgres:16.13-alpine3.23: as a NOSUPERUSER role the statement
-- reported `DELETE 0` while 50,000 anonymous rows were present. Index builds
-- ignore RLS, so the rebuild below would then abort with "could not create
-- unique index ... Duplicate keys exist", the file would roll back as one
-- implicit transaction, and golang-migrate would mark the version DIRTY,
-- wedging every later migrate call. This is the first post-0016 migration to
-- run DML on an RLS-forced data-plane table.
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
DELETE FROM users WHERE is_anonymous;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS users_project_anonymous_last_login_idx;
CREATE UNIQUE INDEX IF NOT EXISTS users_project_email_uidx
    ON users (project_id, lower(email));
DROP INDEX IF EXISTS users_project_email_partial_uidx;

ALTER TABLE users DROP COLUMN IF EXISTS is_anonymous;
