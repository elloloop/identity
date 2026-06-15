-- pre-v1-to-v1.sql
--
-- ============================================================================
-- UNSUPPORTED, BEST-EFFORT, ONE-SHOT legacy-data bridge.
-- ============================================================================
--
-- READ docs/UPGRADE.md FIRST. The supported upgrade path from any pre-v1.0
-- release to v1.0 is a fresh install: there is NO production data on the
-- legacy (tenant-shard / Organization) model, so a backfill is not required
-- and not maintained. This script exists ONLY for the rare developer or early
-- adopter who DID run a pre-v1.0 build against a real Postgres database and
-- wants to keep that data.
--
-- It is provided AS-IS, is NOT covered by any compatibility guarantee, is NOT
-- wired into the boot path or golang-migrate, and is NOT exercised by CI. Run
-- it MANUALLY, ON A COPY of your database, verify the result, and only then
-- consider applying it to anything you care about. If in doubt, do a fresh
-- install instead.
--
-- ----------------------------------------------------------------------------
-- What it does
-- ----------------------------------------------------------------------------
-- The v1.0 schema inverts storage cardinality (ADR-0002): every data-plane
-- table is keyed by `project_id` referencing a control-plane `projects` row,
-- instead of a bare `tenant_id` shard string. Migration 0015 renames the
-- leading `tenant_id` column to `project_id` IN PLACE (it does not rewrite the
-- values) and then adds a FOREIGN KEY to projects(id). On legacy data that FK
-- would fail, because no `projects` row matches the old shard strings.
--
-- This script materializes exactly one `projects` row per distinct legacy
-- `tenant_id` found across the data plane, with:
--
--     projects.id               = <legacy tenant_id>   (so the post-0015 FK holds)
--     projects.storage_scope_id = <legacy tenant_id>   (the physical shard)
--
-- It does NOT rewrite any `tenant_id` values: because the project id is chosen
-- to equal the legacy shard string, the 0015 column rename + FK is satisfied
-- as-is. The data-plane `tenant_id` values become `project_id` values that
-- point at the project rows created here.
--
-- ----------------------------------------------------------------------------
-- Where it runs in the migration sequence
-- ----------------------------------------------------------------------------
-- Run this AFTER migration 0014 and BEFORE migration 0015, i.e.:
--
--   1. identity migrate  ... up to and including 0014   (creates `projects`;
--                                                         drops `organizations`)
--   2. psql -f scripts/upgrade/pre-v1-to-v1.sql          (THIS script)
--   3. identity migrate  ... 0015                        (renames tenant_id ->
--                                                         project_id, adds the
--                                                         FK to projects)
--
-- `identity migrate` applies all pending migrations in one shot, so to insert
-- this step you must stage to 0014 first. With the golang-migrate CLI against
-- the embedded migrations that is, for example:
--
--   migrate -path internal/repo/postgres/migrations -database "$DSN" goto 14
--   psql "$DSN" -v ON_ERROR_STOP=1 -f scripts/upgrade/pre-v1-to-v1.sql
--   migrate -path internal/repo/postgres/migrations -database "$DSN" up
--
-- ----------------------------------------------------------------------------
-- Single-deployment note (the common case)
-- ----------------------------------------------------------------------------
-- A legacy single deployment has exactly one shard string: GATEWAY_DEFAULT_
-- TENANT_ID (default `local`). This script then creates one project whose id
-- AND storage_scope_id both equal that string. Set the v1.0 service config so
-- the default project id matches:
--
--     GATEWAY_DEFAULT_PROJECT_ID = <your legacy GATEWAY_DEFAULT_TENANT_ID>
--     GATEWAY_DEFAULT_TENANT_ID  = <unchanged>
--
-- (In a clean v1.0 install these two are intentionally distinct — id defaults
-- to `default`, storage scope to `local`. When bridging legacy data they must
-- coincide on the legacy shard string, because the data already carries that
-- string and 0015 does not rewrite it.)
--
-- A legacy `mode=multi` deployment has many shard strings; this script creates
-- one project per shard automatically. Each project's id equals its shard
-- string. Review the result and pick whichever shard is your default project
-- for GATEWAY_DEFAULT_PROJECT_ID.
-- ============================================================================

BEGIN;

-- Guard: the control-plane `projects` table must already exist (migration
-- 0013/0014 applied) and the data plane must still be on the legacy column
-- (`users.tenant_id` present, i.e. 0015 NOT yet applied). Fail loudly
-- otherwise rather than corrupt a half-migrated database.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'projects'
    ) THEN
        RAISE EXCEPTION
            'projects table missing: apply migrations up to 0014 before running this script';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'tenant_id'
    ) THEN
        RAISE EXCEPTION
            'users.tenant_id absent: migration 0015 already applied — this bridge must run BEFORE 0015';
    END IF;
END $$;

-- Materialize one Project per distinct legacy shard string, gathered across
-- every data-plane table that carried `tenant_id` in the pre-v1.0 schema. The
-- UNION collapses the same shard appearing in many tables. The project id is
-- the shard string itself so the 0015 column rename + FK is satisfied without
-- any data-plane value rewrite. `users` alone is sufficient for any deployment
-- that ever had a single user; the extra tables only widen the net so a shard
-- that exists solely in, say, audit_events is not missed.
INSERT INTO projects (id, storage_scope_id, name, status, config_json,
                      created_at_ms, updated_at_ms)
SELECT
    s.tenant_id                                 AS id,
    s.tenant_id                                 AS storage_scope_id,
    s.tenant_id                                 AS name,
    'active'                                    AS status,
    '{}'::jsonb                                 AS config_json,
    (extract(epoch FROM now()) * 1000)::bigint  AS created_at_ms,
    (extract(epoch FROM now()) * 1000)::bigint  AS updated_at_ms
FROM (
    SELECT tenant_id FROM users
    UNION
    SELECT tenant_id FROM refresh_tokens
    UNION
    SELECT tenant_id FROM sessions
    UNION
    SELECT tenant_id FROM audit_events
) AS s
WHERE s.tenant_id IS NOT NULL
  AND s.tenant_id <> ''
ON CONFLICT (id) DO NOTHING;

-- Sanity check: every distinct legacy shard now has a matching project, so the
-- FOREIGN KEY that migration 0015 adds (project_id -> projects.id) will hold.
DO $$
DECLARE
    orphan_count bigint;
BEGIN
    SELECT count(*) INTO orphan_count
    FROM (
        SELECT tenant_id FROM users
        UNION
        SELECT tenant_id FROM refresh_tokens
        UNION
        SELECT tenant_id FROM sessions
        UNION
        SELECT tenant_id FROM audit_events
    ) AS s
    WHERE s.tenant_id IS NOT NULL
      AND s.tenant_id <> ''
      AND NOT EXISTS (SELECT 1 FROM projects p WHERE p.id = s.tenant_id);

    IF orphan_count > 0 THEN
        RAISE EXCEPTION
            'still % legacy shard string(s) without a matching project — refusing to commit', orphan_count;
    END IF;
END $$;

COMMIT;

-- After COMMIT: apply migration 0015 to rename tenant_id -> project_id across
-- the data plane and attach the projects FK. The values are already correct
-- (each row's old tenant_id is now a project_id pointing at the project
-- materialized above), so no further data rewrite is needed.
