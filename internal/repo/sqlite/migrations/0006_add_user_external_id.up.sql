-- SCIM externalId (#260): stable IdP-owned identifier, nullable/empty for
-- non-SCIM users. Uniqueness is scoped to the project and only enforced
-- when external_id is non-empty (a partial unique index), so unprovisioned
-- users — all carrying '' — never collide. Mirrors the postgres driver.
ALTER TABLE users
    ADD COLUMN external_id TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX users_project_external_id_uidx
    ON users (project_id, external_id)
    WHERE external_id <> '';

-- Backing index for the SCIM /Users list ORDER BY (created_at_ms ASC, id ASC)
-- within a project, mirroring the postgres driver.
CREATE INDEX users_project_created_id_idx
    ON users (project_id, created_at_ms, id);
