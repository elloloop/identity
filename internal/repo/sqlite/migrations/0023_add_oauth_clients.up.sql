CREATE TABLE oauth_clients (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind = 'native_public'),
    registration_json TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (project_id, id)
);
