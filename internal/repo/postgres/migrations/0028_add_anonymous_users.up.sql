-- Anonymous identity (ADR-0013). A Firebase-style anonymous user is a REAL
-- user row that simply holds no credential: no email, no password, no
-- provider identity. It is reachable only through its refresh token, and it
-- keeps its id when it is later upgraded to a permanent account, so every
-- row a client wrote against that id survives the upgrade.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_anonymous BOOLEAN NOT NULL DEFAULT FALSE;

-- Email uniqueness now applies only to users that HAVE an email. Anonymous
-- users carry '', and any number of them must coexist inside one project;
-- the old total index made the second anonymous sign-in a duplicate-key
-- error. The predicate mirrors users_project_external_id_uidx (0021): the
-- constraint holds exactly where the value is meaningful.
--
-- The rebuild takes a brief SHARE lock on `users` (blocks writes, allows
-- reads) for the duration of the build. Acceptable under the runner's
-- advisory lock; a deployment with a large `users` table should pre-build
-- the replacement with CREATE INDEX CONCURRENTLY and let IF NOT EXISTS
-- no-op. The DROP is second so the uniqueness invariant is never
-- unenforced, not even briefly.
CREATE UNIQUE INDEX IF NOT EXISTS users_project_email_partial_uidx
    ON users (project_id, lower(email))
    WHERE email <> '';
DROP INDEX IF EXISTS users_project_email_uidx;

-- Backing index for the anonymous-retention sweep, which scans one project's
-- anonymous users by last activity. Partial, so it stays small on a
-- deployment that never enables anonymous sign-in.
CREATE INDEX IF NOT EXISTS users_project_anonymous_last_login_idx
    ON users (project_id, last_login_at_ms)
    WHERE is_anonymous;
