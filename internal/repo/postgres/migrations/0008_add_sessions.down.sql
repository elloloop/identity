-- 0008_add_sessions.down.sql

DROP INDEX IF EXISTS sessions_tenant_user_idx;
DROP INDEX IF EXISTS sessions_tenant_sid_uidx;
DROP TABLE IF EXISTS sessions;
