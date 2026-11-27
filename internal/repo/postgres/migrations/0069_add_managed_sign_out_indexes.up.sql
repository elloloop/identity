-- 0069_add_managed_sign_out_indexes.up.sql
--
-- Suspending, removing or resetting a managed account ends the sign-ins
-- already under way for it and its agents: approved QR hand-offs, unredeemed
-- OAuth one-time codes and pending sign-in challenges, found by user. These
-- partial indexes serve those lookups, so each scans only the account's live
-- rows instead of the project's. Each CREATE INDEX takes SHARE on its table,
-- blocking writes, not reads, while it builds; lock_timeout bounds the wait
-- to acquire it. To build them without blocking writes, run the statements in
-- docs/UPGRADE.md before upgrading; the migration then does nothing.
SET LOCAL lock_timeout = '10s';

CREATE INDEX IF NOT EXISTS qr_login_sessions_approved_user_idx
    ON qr_login_sessions (project_id, user_id)
    WHERE status = 'approved';

CREATE INDEX IF NOT EXISTS oauth_one_time_codes_unconsumed_user_idx
    ON oauth_one_time_codes (project_id, user_id)
    WHERE consumed_at_ms = 0;

CREATE INDEX IF NOT EXISTS login_challenges_project_user_idx
    ON login_challenges (project_id, user_id);
