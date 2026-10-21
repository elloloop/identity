-- 0026_add_oauth_one_time_code_challenge.up.sql
--
-- SQLite mirror of postgres 0043: the S256 PKCE challenge a one-time code is
-- bound to, or empty when the app sent none.
ALTER TABLE oauth_one_time_codes
    ADD COLUMN code_challenge TEXT NOT NULL DEFAULT '';
