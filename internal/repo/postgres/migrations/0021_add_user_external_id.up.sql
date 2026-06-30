-- SCIM externalId (#260): a stable, IdP-owned identifier an external IdP
-- (Okta/Entra/Google) assigns so it can lifecycle-manage an account
-- independently of email changes. Nullable/empty for users not provisioned
-- via SCIM. Uniqueness is scoped to the project (the isolation shard) and
-- only enforced when external_id is non-empty, so any number of
-- unprovisioned users coexist.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS external_id TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS users_project_external_id_uidx
    ON users (project_id, external_id)
    WHERE external_id <> '';

-- Backing index for the SCIM /Users list ORDER BY (created_at_ms ASC, id ASC)
-- within a project: the unfiltered list page is the hot path an IdP polls, so a
-- composite index lets the keyset/offset scan run without a sort.
CREATE INDEX IF NOT EXISTS users_project_created_id_idx
    ON users (project_id, created_at_ms, id);
