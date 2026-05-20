-- 0009_add_oauth_one_time_codes.down.sql

DROP INDEX IF EXISTS oauth_one_time_codes_tenant_expires_idx;
DROP INDEX IF EXISTS oauth_one_time_codes_tenant_code_uidx;
DROP TABLE IF EXISTS oauth_one_time_codes;
