ALTER TABLE groups
    ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS admin_help_requests (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    email              TEXT NOT NULL,
    reason             TEXT NOT NULL DEFAULT '',
    source_ip          TEXT NOT NULL DEFAULT '',
    user_agent         TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending','resolved','rejected')),
    resolved_by        TEXT NOT NULL DEFAULT '',
    resolution_notes   TEXT NOT NULL DEFAULT '',
    resolved_at_ms     BIGINT NOT NULL DEFAULT 0,
    created_at_ms      BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS admin_help_requests_status_idx
    ON admin_help_requests (tenant_id, status, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS admin_help_requests_email_idx
    ON admin_help_requests (tenant_id, lower(email), created_at_ms DESC);
