-- 0008_add_refresh_token_sid.down.sql
ALTER TABLE refresh_tokens
    DROP COLUMN sid;
