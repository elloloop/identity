-- 0029_add_sso_sessions.down.sql

DROP POLICY IF EXISTS sso_sessions_project_isolation ON sso_sessions;
DROP INDEX IF EXISTS sso_sessions_project_expires_idx;
DROP INDEX IF EXISTS sso_sessions_project_user_idx;
DROP INDEX IF EXISTS sso_sessions_project_token_uidx;
DROP TABLE IF EXISTS sso_sessions;
