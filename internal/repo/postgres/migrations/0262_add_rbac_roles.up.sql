-- 0262_add_rbac_roles.up.sql
--
-- RBAC: project-scoped custom roles and per-user role assignments.
--
-- Additive to the legacy free-text users.role field: a custom role names an
-- explicit permission set, and an assignment binds a user to at most one
-- custom role. The legacy admin/owner roles remain a full-access superset
-- enforced in the service layer, so existing behaviour is unchanged.

CREATE TABLE rbac_roles (
    id            TEXT NOT NULL,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    permissions   TEXT[] NOT NULL DEFAULT '{}',
    created_at_ms  BIGINT NOT NULL,
    updated_at_ms  BIGINT NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (project_id, name)
);

CREATE TABLE rbac_role_assignments (
    id            TEXT NOT NULL,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_name     TEXT NOT NULL,
    created_at_ms  BIGINT NOT NULL,
    PRIMARY KEY (id),
    -- A user has at most one custom role per project.
    UNIQUE (project_id, user_id),
    -- An assignment references an existing role; deleting the role cascades
    -- the dangling assignments away.
    FOREIGN KEY (project_id, role_name)
        REFERENCES rbac_roles (project_id, name) ON DELETE CASCADE
);

CREATE INDEX rbac_role_assignments_role_idx
    ON rbac_role_assignments (project_id, role_name);

-- Row-Level Security: same per-project isolation policy as every other
-- data-plane table (migration 0016). FORCE so the owning role is bound too.
ALTER TABLE rbac_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY rbac_roles_project_isolation ON rbac_roles
    USING (project_id = current_setting('app.current_project_id', true));

ALTER TABLE rbac_role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_role_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY rbac_role_assignments_project_isolation ON rbac_role_assignments
    USING (project_id = current_setting('app.current_project_id', true));
