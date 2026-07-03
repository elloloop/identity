-- 0005_add_refresh_token_session_start.down.sql
ALTER TABLE refresh_tokens
    DROP COLUMN session_started_at_ms;
