-- 0031_add_guardian_edges.up.sql
--
-- Guardian edges: the authorization fact
-- that guardian_user_id manages child_user_id. Unlike parental_consents —
-- an audit/compliance artifact that deliberately survives user deletion — an
-- edge is live authorization state and dies with either account it
-- references, hence the users(id) FKs with ON DELETE CASCADE.
--
-- The backfill derives one edge per active (non-revoked) parental_consents
-- row. The joins against users exist because consent rows outlive the users
-- they reference (by design): a consent whose adult or child has since been
-- deleted must NOT gain an edge — there is no live account left to
-- authorize. granted_at_ms becomes the edge's created_at_ms. ON CONFLICT DO
-- NOTHING keeps the backfill idempotent on re-run.
--
-- RLS must be suspended around the backfill: parental_consents and users are
-- RLS-FORCED tables whose policies key on current_setting(
-- 'app.current_project_id'), and the migration runner's connection never
-- sets that GUC, so under a non-superuser role the SELECT would fail closed
-- and silently backfill NOTHING (the same trap migration 0028's down
-- documents). golang-migrate's pgx driver runs each migration in one
-- transaction, so the DISABLE/ENABLE pairs below roll back with the rest on
-- failure.

CREATE TABLE guardian_edges (
    project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    guardian_user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    child_user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at_ms     BIGINT NOT NULL,
    PRIMARY KEY (project_id, guardian_user_id, child_user_id)
);
CREATE INDEX guardian_edges_project_child_idx
    ON guardian_edges (project_id, child_user_id);

ALTER TABLE parental_consents DISABLE ROW LEVEL SECURITY;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

INSERT INTO guardian_edges (project_id, guardian_user_id, child_user_id, created_at_ms)
SELECT pc.project_id, pc.consenting_user_id, pc.child_user_id, pc.granted_at_ms
FROM parental_consents pc
JOIN users g ON g.id = pc.consenting_user_id AND g.project_id = pc.project_id
JOIN users c ON c.id = pc.child_user_id AND c.project_id = pc.project_id
WHERE pc.revoked_at_ms = 0
ON CONFLICT DO NOTHING;

ALTER TABLE parental_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE parental_consents FORCE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- Row-level security: pin every row to the request's project, matching the
-- data-plane isolation posture migration 0016 established for the other
-- tables.
ALTER TABLE guardian_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE guardian_edges FORCE ROW LEVEL SECURITY;
CREATE POLICY guardian_edges_project_isolation ON guardian_edges
    USING (project_id = current_setting('app.current_project_id', true));
