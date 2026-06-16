-- 0003_add_rbac_roles.up.sql
--
-- RBAC: project-scoped custom roles and per-user role assignments.
-- SQLite has no array type, so permissions are stored as a JSON text column.

CREATE TABLE rbac_roles (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    permissions   TEXT NOT NULL DEFAULT '[]',
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX rbac_roles_project_name_uidx ON rbac_roles (project_id, name);

CREATE TABLE rbac_role_assignments (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_name     TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    FOREIGN KEY (project_id, role_name)
        REFERENCES rbac_roles (project_id, name) ON DELETE CASCADE
);
CREATE UNIQUE INDEX rbac_role_assignments_project_user_uidx
    ON rbac_role_assignments (project_id, user_id);
CREATE INDEX rbac_role_assignments_role_idx
    ON rbac_role_assignments (project_id, role_name);
