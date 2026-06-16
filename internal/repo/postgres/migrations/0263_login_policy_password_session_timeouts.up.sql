-- Per-tenant password complexity + session timeout policy fields.
-- Additive to login_policies (migration 0013). All default to 0/false, which
-- means "use the global behavior" so existing rows are unaffected.
ALTER TABLE login_policies
    ADD COLUMN password_min_length              INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN password_require_classes         BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN session_idle_timeout_seconds     BIGINT  NOT NULL DEFAULT 0,
    ADD COLUMN session_absolute_timeout_seconds BIGINT  NOT NULL DEFAULT 0;
