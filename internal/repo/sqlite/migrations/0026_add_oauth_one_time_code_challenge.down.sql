-- 0026_add_oauth_one_time_code_challenge.down.sql

ALTER TABLE oauth_one_time_codes DROP COLUMN code_challenge;
