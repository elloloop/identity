-- 0069_add_managed_sign_out_indexes.down.sql
SET LOCAL lock_timeout = '10s';

DROP INDEX IF EXISTS login_challenges_project_user_idx;
DROP INDEX IF EXISTS oauth_one_time_codes_unconsumed_user_idx;
DROP INDEX IF EXISTS qr_login_sessions_approved_user_idx;
