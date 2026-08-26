-- 0016_add_guardian_edges.up.sql
--
-- SQLite mirror of postgres 0031: guardian edges (guardian_user_id manages
-- child_user_id). Unlike parental_consents — an audit artifact retained after
-- user deletion — an edge dies with either account it references (FKs with
-- ON DELETE CASCADE; foreign_keys is enabled per connection).
--
-- The backfill joins against users because consent rows deliberately outlive
-- the users they reference: a consent whose adult or child was deleted must
-- not gain an edge. ON CONFLICT DO NOTHING keeps a re-run idempotent.
CREATE TABLE guardian_edges (
    project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    guardian_user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    child_user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at_ms     INTEGER NOT NULL,
    PRIMARY KEY (project_id, guardian_user_id, child_user_id)
);
CREATE INDEX guardian_edges_project_child_idx
    ON guardian_edges (project_id, child_user_id);

INSERT INTO guardian_edges (project_id, guardian_user_id, child_user_id, created_at_ms)
SELECT pc.project_id, pc.consenting_user_id, pc.child_user_id, pc.granted_at_ms
FROM parental_consents pc
JOIN users g ON g.id = pc.consenting_user_id AND g.project_id = pc.project_id
JOIN users c ON c.id = pc.child_user_id AND c.project_id = pc.project_id
WHERE pc.revoked_at_ms = 0
ON CONFLICT DO NOTHING;
