-- 0027_add_refresh_token_auth_time.down.sql
ALTER TABLE refresh_tokens
    DROP COLUMN auth_time_ms;
