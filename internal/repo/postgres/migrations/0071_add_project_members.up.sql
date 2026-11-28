-- 0071_add_project_members.up.sql
--
-- A project's members are the console accounts that manage it (ADR-0022):
-- the owner who created it, and the admins an owner adds. A member is an
-- account of the deployment's own (default) project, which is where console
-- accounts live, so user_id names a row of users whatever project the
-- membership is of. The project console authorizes every call by a row
-- here; the operator's admin secret needs none.
--
-- Like tenant_memberships, it is a governance table with no row-level
-- security (0016): it is read by (user_id) across projects to list the
-- projects an account manages, which no single project's scope could serve.
-- Its rows go with the project or the account they name. The primary key
-- serves the membership check; the user_id index serves the listing, the
-- per-owner count CreateProject is limited by, and the cascade when an
-- account is deleted.
--
-- Locks: CREATE TABLE with REFERENCES takes SHARE ROW EXCLUSIVE on projects
-- and users while it adds the foreign-key triggers, blocking writes to them,
-- not reads, for as long as the catalog change takes. lock_timeout bounds
-- the wait to acquire them, as in 0052. On a timeout the file rolls back and
-- version 71 is left dirty: `identity migrate force 70`, then
-- `identity migrate` again.
SET LOCAL lock_timeout = '10s';

CREATE TABLE IF NOT EXISTS project_members (
    project_id     TEXT   NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id        TEXT   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role           TEXT   NOT NULL CHECK (role IN ('owner','admin')),
    created_at_ms  BIGINT NOT NULL,
    PRIMARY KEY (project_id, user_id)
);
CREATE INDEX IF NOT EXISTS project_members_user_idx
    ON project_members (user_id, role);
