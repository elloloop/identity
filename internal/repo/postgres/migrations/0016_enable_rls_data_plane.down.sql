-- 0016_enable_rls_data_plane.down.sql
--
-- Reverse 0016: drop the per-table project-isolation policy and disable
-- row-level security on every data-plane table. After this runs the only
-- isolation boundary is again the application-level `WHERE project_id = $1`
-- predicate (ADR-0002). DROP POLICY removes the policy; ALTER TABLE …
-- NO FORCE / DISABLE ROW LEVEL SECURITY undoes the FORCE + ENABLE from
-- the up migration so the table behaves exactly as it did before 0016.

-- ── users ──────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS users_project_isolation ON users;
ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

-- ── refresh_tokens ─────────────────────────────────────────────────────
DROP POLICY IF EXISTS refresh_tokens_project_isolation ON refresh_tokens;
ALTER TABLE refresh_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens DISABLE ROW LEVEL SECURITY;

-- ── sessions ───────────────────────────────────────────────────────────
DROP POLICY IF EXISTS sessions_project_isolation ON sessions;
ALTER TABLE sessions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE sessions DISABLE ROW LEVEL SECURITY;

-- ── password_reset_tokens ──────────────────────────────────────────────
DROP POLICY IF EXISTS password_reset_tokens_project_isolation ON password_reset_tokens;
ALTER TABLE password_reset_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens DISABLE ROW LEVEL SECURITY;

-- ── email_verification_tokens ──────────────────────────────────────────
DROP POLICY IF EXISTS email_verification_tokens_project_isolation ON email_verification_tokens;
ALTER TABLE email_verification_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE email_verification_tokens DISABLE ROW LEVEL SECURITY;

-- ── email_change_tokens ────────────────────────────────────────────────
DROP POLICY IF EXISTS email_change_tokens_project_isolation ON email_change_tokens;
ALTER TABLE email_change_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE email_change_tokens DISABLE ROW LEVEL SECURITY;

-- ── oauth_identities ───────────────────────────────────────────────────
DROP POLICY IF EXISTS oauth_identities_project_isolation ON oauth_identities;
ALTER TABLE oauth_identities NO FORCE ROW LEVEL SECURITY;
ALTER TABLE oauth_identities DISABLE ROW LEVEL SECURITY;

-- ── groups ─────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS groups_project_isolation ON groups;
ALTER TABLE groups NO FORCE ROW LEVEL SECURITY;
ALTER TABLE groups DISABLE ROW LEVEL SECURITY;

-- ── group_memberships ──────────────────────────────────────────────────
DROP POLICY IF EXISTS group_memberships_project_isolation ON group_memberships;
ALTER TABLE group_memberships NO FORCE ROW LEVEL SECURITY;
ALTER TABLE group_memberships DISABLE ROW LEVEL SECURITY;

-- ── audit_events ───────────────────────────────────────────────────────
DROP POLICY IF EXISTS audit_events_project_isolation ON audit_events;
ALTER TABLE audit_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events DISABLE ROW LEVEL SECURITY;

-- ── user_invitations ───────────────────────────────────────────────────
DROP POLICY IF EXISTS user_invitations_project_isolation ON user_invitations;
ALTER TABLE user_invitations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE user_invitations DISABLE ROW LEVEL SECURITY;

-- ── qr_login_sessions ──────────────────────────────────────────────────
DROP POLICY IF EXISTS qr_login_sessions_project_isolation ON qr_login_sessions;
ALTER TABLE qr_login_sessions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE qr_login_sessions DISABLE ROW LEVEL SECURITY;

-- ── passkeys ───────────────────────────────────────────────────────────
DROP POLICY IF EXISTS passkeys_project_isolation ON passkeys;
ALTER TABLE passkeys NO FORCE ROW LEVEL SECURITY;
ALTER TABLE passkeys DISABLE ROW LEVEL SECURITY;

-- ── passkey_challenges ─────────────────────────────────────────────────
DROP POLICY IF EXISTS passkey_challenges_project_isolation ON passkey_challenges;
ALTER TABLE passkey_challenges NO FORCE ROW LEVEL SECURITY;
ALTER TABLE passkey_challenges DISABLE ROW LEVEL SECURITY;

-- ── totp_secrets ───────────────────────────────────────────────────────
DROP POLICY IF EXISTS totp_secrets_project_isolation ON totp_secrets;
ALTER TABLE totp_secrets NO FORCE ROW LEVEL SECURITY;
ALTER TABLE totp_secrets DISABLE ROW LEVEL SECURITY;

-- ── recovery_codes ─────────────────────────────────────────────────────
DROP POLICY IF EXISTS recovery_codes_project_isolation ON recovery_codes;
ALTER TABLE recovery_codes NO FORCE ROW LEVEL SECURITY;
ALTER TABLE recovery_codes DISABLE ROW LEVEL SECURITY;

-- ── login_challenges ───────────────────────────────────────────────────
DROP POLICY IF EXISTS login_challenges_project_isolation ON login_challenges;
ALTER TABLE login_challenges NO FORCE ROW LEVEL SECURITY;
ALTER TABLE login_challenges DISABLE ROW LEVEL SECURITY;

-- ── admin_help_requests ────────────────────────────────────────────────
DROP POLICY IF EXISTS admin_help_requests_project_isolation ON admin_help_requests;
ALTER TABLE admin_help_requests NO FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_help_requests DISABLE ROW LEVEL SECURITY;

-- ── identity_verifications ─────────────────────────────────────────────
DROP POLICY IF EXISTS identity_verifications_project_isolation ON identity_verifications;
ALTER TABLE identity_verifications NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_verifications DISABLE ROW LEVEL SECURITY;

-- ── oauth_one_time_codes ───────────────────────────────────────────────
DROP POLICY IF EXISTS oauth_one_time_codes_project_isolation ON oauth_one_time_codes;
ALTER TABLE oauth_one_time_codes NO FORCE ROW LEVEL SECURITY;
ALTER TABLE oauth_one_time_codes DISABLE ROW LEVEL SECURITY;

-- ── email_login_codes ──────────────────────────────────────────────────
DROP POLICY IF EXISTS email_login_codes_project_isolation ON email_login_codes;
ALTER TABLE email_login_codes NO FORCE ROW LEVEL SECURITY;
ALTER TABLE email_login_codes DISABLE ROW LEVEL SECURITY;

-- ── magic_link_tokens ──────────────────────────────────────────────────
DROP POLICY IF EXISTS magic_link_tokens_project_isolation ON magic_link_tokens;
ALTER TABLE magic_link_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE magic_link_tokens DISABLE ROW LEVEL SECURITY;

-- ── phone_verification_codes ───────────────────────────────────────────
DROP POLICY IF EXISTS phone_verification_codes_project_isolation ON phone_verification_codes;
ALTER TABLE phone_verification_codes NO FORCE ROW LEVEL SECURITY;
ALTER TABLE phone_verification_codes DISABLE ROW LEVEL SECURITY;
