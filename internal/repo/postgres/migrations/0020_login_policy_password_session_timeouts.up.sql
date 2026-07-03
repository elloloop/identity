-- Per-tenant password complexity + session timeout policy.
--
-- login_policies (migration 0013) gains the per-tenant knobs the login path
-- enforces: a tightened minimum password length and idle/absolute session
-- timeouts. All default to 0, which means "use the global behavior", so
-- existing rows are unaffected.
ALTER TABLE login_policies
    ADD COLUMN password_min_length              INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN session_idle_timeout_seconds     BIGINT  NOT NULL DEFAULT 0,
    ADD COLUMN session_absolute_timeout_seconds BIGINT  NOT NULL DEFAULT 0;

-- refresh_tokens gains a session-start anchor for the absolute timeout. Unlike
-- created_at_ms (which is re-stamped on every rotation), session_started_at_ms
-- is copied unchanged across rotations so the absolute timeout is measured from
-- the original login, not the latest refresh. 0 means "no anchor recorded"
-- (legacy rows; the absolute timeout is skipped until the next rotation
-- re-anchors them).
ALTER TABLE refresh_tokens
    ADD COLUMN session_started_at_ms BIGINT NOT NULL DEFAULT 0;
