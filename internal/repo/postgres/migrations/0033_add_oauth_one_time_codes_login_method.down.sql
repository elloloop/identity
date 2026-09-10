-- 0033_add_oauth_one_time_codes_login_method.down.sql

ALTER TABLE oauth_one_time_codes
    DROP COLUMN IF EXISTS login_method;
