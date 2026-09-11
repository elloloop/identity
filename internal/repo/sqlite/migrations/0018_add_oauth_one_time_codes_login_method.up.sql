-- 0018_add_oauth_one_time_codes_login_method.up.sql
--
-- SQLite mirror of postgres 0033: record which hosted flow minted a handover
-- code ('oauth' or 'magic_link') so redeem enforces that flow's login policy
-- and audit event. Rows that predate the column were minted by OAuth, which
-- the default preserves.
ALTER TABLE oauth_one_time_codes
    ADD COLUMN login_method TEXT NOT NULL DEFAULT 'oauth'
        CHECK (login_method IN ('oauth', 'magic_link'));
