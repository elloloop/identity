-- See postgres 0028 down: anonymous users share the empty email that the
-- restored total unique index forbids more than one of, and hold no
-- credential to sign back in with, so they are deleted rather than left to
-- break the index rebuild. (SQLite has no RLS, so the delete needs no
-- equivalent of the postgres file's ALTER TABLE dance.)
--
-- Wrapped in an explicit transaction, following the 0009 precedent: the
-- sqlite runner is NoTxWrap, so without BEGIN/COMMIT the DELETE commits on
-- its own and a failure in the index rebuild below would leave the rows
-- gone, the new index gone, the old index never restored, and the version
-- dirty. Either the whole rollback happens or none of it does.
BEGIN;

DELETE FROM users WHERE is_anonymous;

DROP INDEX IF EXISTS users_project_created_id_nonanon_idx;
DROP INDEX IF EXISTS users_project_anonymous_last_seen_idx;
CREATE UNIQUE INDEX IF NOT EXISTS users_project_email_uidx
    ON users (project_id, lower(email));
DROP INDEX IF EXISTS users_project_email_partial_uidx;

ALTER TABLE users DROP COLUMN anonymous_last_seen_ms;
ALTER TABLE users DROP COLUMN is_anonymous;

COMMIT;
