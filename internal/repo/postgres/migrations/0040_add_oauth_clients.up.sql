CREATE TABLE oauth_clients (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    id TEXT COLLATE "C" NOT NULL,
    kind TEXT NOT NULL CHECK (kind = 'native_public'),
    registration_json JSONB NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (project_id, id)
);
ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_clients FORCE ROW LEVEL SECURITY;
CREATE POLICY oauth_clients_project_isolation ON oauth_clients
    USING (project_id = current_setting('app.current_project_id', true));
