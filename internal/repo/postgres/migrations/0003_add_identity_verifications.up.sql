CREATE TABLE IF NOT EXISTS identity_verifications (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    verification_id      TEXT NOT NULL,
    user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider             TEXT NOT NULL,
    provider_session_id  TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL,
    created_at_ms        BIGINT NOT NULL,
    updated_at_ms        BIGINT NOT NULL,
    completed_at_ms      BIGINT NOT NULL DEFAULT 0,
    rejection_reason     TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idv_tenant_verification_uidx
    ON identity_verifications (tenant_id, verification_id);
CREATE INDEX IF NOT EXISTS idv_user_created_idx
    ON identity_verifications (tenant_id, user_id, created_at_ms DESC);
