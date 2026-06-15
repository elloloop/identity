-- 0016_enable_rls_data_plane.up.sql
--
-- Defense-in-depth: Postgres Row-Level Security on every data-plane table.
--
-- The mandatory `WHERE project_id = $1` predicate injected at the
-- RepositoryForProject boundary (internal/repo/postgres) is the PRIMARY
-- isolation boundary (ADR-0002). RLS is a SECOND, independent boundary
-- enforced by the database itself: even a query that forgets the predicate
-- — a future code path, an ad-hoc psql session, an injection — can only ever
-- touch rows of the project bound to the current connection.
--
-- Mechanism
-- ---------
-- Each table is given a single permissive policy:
--
--     USING (project_id = current_setting('app.current_project_id', true))
--
-- The Go postgres driver sets the `app.current_project_id` GUC to the
-- repository's bound project on every connection it checks out of the pool
-- (internal/repo/postgres/rls.go: a pgxpool PrepareConn hook runs on every
-- Acquire and re-sets the GUC, so a project can never leak across pooled
-- connections — the next acquirer overwrites it before its query runs).
--
-- FAIL CLOSED: the second arg to current_setting is `missing_ok = true`, so
-- an UNSET GUC yields SQL NULL rather than raising. `project_id = NULL` is
-- NULL (never true), so a connection that never set the GUC matches NO rows
-- on any table. A forgotten SET can only ever cause "zero rows", never a
-- cross-project leak.
--
-- FORCE ROW LEVEL SECURITY
-- ------------------------
-- A table's OWNER (and any BYPASSRLS role) is exempt from RLS by default.
-- identity creates these tables as the connecting role, so that role owns
-- them and would silently bypass the policy. FORCE makes the policy apply
-- to the owner too, which is what makes this boundary real in the common
-- single-role deployment AND in the test harness (which connects as the
-- owner). See docs/postgres-rls.md for the role requirement: the
-- application role must NOT have the BYPASSRLS attribute, or RLS is a no-op
-- for it regardless of FORCE.
--
-- The same policy text is applied to all 23 data-plane tables (every table
-- whose leading shard column was renamed tenant_id -> project_id in
-- migration 0015). Control-plane tables (projects, tenants, domains,
-- project_credentials, project_auth_domains, platform_admins, login_policies,
-- tenant_memberships, tenant_invitations) are platform-global by design and
-- intentionally have NO project_id and NO RLS: a request resolves its project
-- from them BEFORE any data-plane query runs.
--
-- NOTE on TRUNCATE: RLS never applies to TRUNCATE (it is governed by table
-- privileges, not row policies), so test/admin truncation paths are
-- unaffected by these policies.

-- ── users ──────────────────────────────────────────────────────────────
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_project_isolation ON users
    USING (project_id = current_setting('app.current_project_id', true));

-- ── refresh_tokens ─────────────────────────────────────────────────────
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY refresh_tokens_project_isolation ON refresh_tokens
    USING (project_id = current_setting('app.current_project_id', true));

-- ── sessions ───────────────────────────────────────────────────────────
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sessions_project_isolation ON sessions
    USING (project_id = current_setting('app.current_project_id', true));

-- ── password_reset_tokens ──────────────────────────────────────────────
ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY password_reset_tokens_project_isolation ON password_reset_tokens
    USING (project_id = current_setting('app.current_project_id', true));

-- ── email_verification_tokens ──────────────────────────────────────────
ALTER TABLE email_verification_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_verification_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY email_verification_tokens_project_isolation ON email_verification_tokens
    USING (project_id = current_setting('app.current_project_id', true));

-- ── email_change_tokens ────────────────────────────────────────────────
ALTER TABLE email_change_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_change_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY email_change_tokens_project_isolation ON email_change_tokens
    USING (project_id = current_setting('app.current_project_id', true));

-- ── oauth_identities ───────────────────────────────────────────────────
ALTER TABLE oauth_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY oauth_identities_project_isolation ON oauth_identities
    USING (project_id = current_setting('app.current_project_id', true));

-- ── groups ─────────────────────────────────────────────────────────────
ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_project_isolation ON groups
    USING (project_id = current_setting('app.current_project_id', true));

-- ── group_memberships ──────────────────────────────────────────────────
ALTER TABLE group_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY group_memberships_project_isolation ON group_memberships
    USING (project_id = current_setting('app.current_project_id', true));

-- ── audit_events ───────────────────────────────────────────────────────
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_project_isolation ON audit_events
    USING (project_id = current_setting('app.current_project_id', true));

-- ── user_invitations ───────────────────────────────────────────────────
ALTER TABLE user_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY user_invitations_project_isolation ON user_invitations
    USING (project_id = current_setting('app.current_project_id', true));

-- ── qr_login_sessions ──────────────────────────────────────────────────
ALTER TABLE qr_login_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE qr_login_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY qr_login_sessions_project_isolation ON qr_login_sessions
    USING (project_id = current_setting('app.current_project_id', true));

-- ── passkeys ───────────────────────────────────────────────────────────
ALTER TABLE passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkeys FORCE ROW LEVEL SECURITY;
CREATE POLICY passkeys_project_isolation ON passkeys
    USING (project_id = current_setting('app.current_project_id', true));

-- ── passkey_challenges ─────────────────────────────────────────────────
ALTER TABLE passkey_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY passkey_challenges_project_isolation ON passkey_challenges
    USING (project_id = current_setting('app.current_project_id', true));

-- ── totp_secrets ───────────────────────────────────────────────────────
ALTER TABLE totp_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE totp_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY totp_secrets_project_isolation ON totp_secrets
    USING (project_id = current_setting('app.current_project_id', true));

-- ── recovery_codes ─────────────────────────────────────────────────────
ALTER TABLE recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_codes_project_isolation ON recovery_codes
    USING (project_id = current_setting('app.current_project_id', true));

-- ── login_challenges ───────────────────────────────────────────────────
ALTER TABLE login_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY login_challenges_project_isolation ON login_challenges
    USING (project_id = current_setting('app.current_project_id', true));

-- ── admin_help_requests ────────────────────────────────────────────────
ALTER TABLE admin_help_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_help_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_help_requests_project_isolation ON admin_help_requests
    USING (project_id = current_setting('app.current_project_id', true));

-- ── identity_verifications ─────────────────────────────────────────────
ALTER TABLE identity_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_verifications FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_verifications_project_isolation ON identity_verifications
    USING (project_id = current_setting('app.current_project_id', true));

-- ── oauth_one_time_codes ───────────────────────────────────────────────
ALTER TABLE oauth_one_time_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_one_time_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY oauth_one_time_codes_project_isolation ON oauth_one_time_codes
    USING (project_id = current_setting('app.current_project_id', true));

-- ── email_login_codes ──────────────────────────────────────────────────
ALTER TABLE email_login_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_login_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY email_login_codes_project_isolation ON email_login_codes
    USING (project_id = current_setting('app.current_project_id', true));

-- ── magic_link_tokens ──────────────────────────────────────────────────
ALTER TABLE magic_link_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE magic_link_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY magic_link_tokens_project_isolation ON magic_link_tokens
    USING (project_id = current_setting('app.current_project_id', true));

-- ── phone_verification_codes ───────────────────────────────────────────
ALTER TABLE phone_verification_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE phone_verification_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY phone_verification_codes_project_isolation ON phone_verification_codes
    USING (project_id = current_setting('app.current_project_id', true));
