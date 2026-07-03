-- refresh_tokens gains a session-start anchor for the per-tenant absolute
-- session timeout. Unlike created_at_ms (re-stamped on every rotation),
-- session_started_at_ms is copied unchanged across rotations so the absolute
-- timeout is measured from the original login, not the latest refresh. 0 means
-- "no anchor recorded" (legacy rows; the absolute timeout is skipped until the
-- next rotation re-anchors them).
ALTER TABLE refresh_tokens ADD COLUMN session_started_at_ms INTEGER NOT NULL DEFAULT 0;
