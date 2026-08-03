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

-- The anonymous activity clock gets its OWN column rather than riding
-- last_login_at_ms. Postgres computes HOT-update eligibility from the union
-- of columns indexed by ANY index on the table and ignores partial-index
-- predicates, so an index over last_login_at_ms — even one predicated
-- WHERE is_anonymous — would make every ordinary login's
-- {last_login_at_ms, updated_at_ms} stamp a non-HOT update, writing a tuple
-- into every index on the busiest table in the system, on every deployment,
-- anonymous or not (measured: 20000/20000 HOT before, 0 after). A separate
-- column confines the non-HOT cost to anonymous refreshes, which are the
-- only writes that need the clock.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS anonymous_last_seen_ms BIGINT NOT NULL DEFAULT 0;

-- Backing index for the anonymous-retention sweep, which scans one project's
-- anonymous users by last activity. Partial, so it stays small on a
-- deployment that never enables anonymous sign-in.
CREATE INDEX IF NOT EXISTS users_project_anonymous_last_seen_idx
    ON users (project_id, anonymous_last_seen_ms)
    WHERE is_anonymous;

-- Backing index for the complement of the sweep predicate. userFilterWhere
-- appends `NOT is_anonymous` to every ListUsers/CountUsers query, and SCIM
-- calls CountUsers on every /Users list request to fill totalResults — so
-- without this the predicate turns an index-only scan into a sequential scan
-- of the project's users, and the added filter makes the planner abandon the
-- ordered index for deep pages. Partial on the complement so it carries no
-- anonymous rows, which makes it smaller than the total index it replaces
-- for this access path.
CREATE INDEX IF NOT EXISTS users_project_created_id_nonanon_idx
    ON users (project_id, created_at_ms, id)
    WHERE NOT is_anonymous;
