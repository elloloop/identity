-- 0070_add_managed_help_notices.down.sql
--
-- Drops the record of help-request notices sent to tenants about their
-- managed accounts. With it gone, the next requests start their daily counts
-- from zero.
SET LOCAL lock_timeout = '10s';

DROP TABLE IF EXISTS managed_help_notices;
