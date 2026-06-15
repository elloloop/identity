-- 0015_invert_tenant_to_project.down.sql
--
-- Reverse 0015: drop the project_id → projects(id) foreign keys, rename the
-- `*_project_*` indexes back to their `*_tenant_*` names, and rename the
-- project_id column back to tenant_id on every data-plane table. Mirrors the
-- up migration exactly so the chain round-trips. Order is the inverse of the
-- up migration (drop FK first so the rename is unconstrained).

-- ── phone_verification_codes ───────────────────────────────────────────
ALTER TABLE phone_verification_codes DROP CONSTRAINT phone_verification_codes_project_fk;
ALTER INDEX phone_verification_codes_project_user_uidx RENAME TO phone_verification_codes_tenant_user_uidx;
ALTER INDEX phone_verification_codes_project_expires_idx RENAME TO phone_verification_codes_tenant_expires_idx;
ALTER TABLE phone_verification_codes RENAME COLUMN project_id TO tenant_id;

-- ── magic_link_tokens ──────────────────────────────────────────────────
ALTER TABLE magic_link_tokens DROP CONSTRAINT magic_link_tokens_project_fk;
ALTER INDEX magic_link_tokens_project_token_uidx RENAME TO magic_link_tokens_tenant_token_uidx;
ALTER INDEX magic_link_tokens_project_expires_idx RENAME TO magic_link_tokens_tenant_expires_idx;
ALTER TABLE magic_link_tokens RENAME COLUMN project_id TO tenant_id;

-- ── email_login_codes ──────────────────────────────────────────────────
ALTER TABLE email_login_codes DROP CONSTRAINT email_login_codes_project_fk;
ALTER INDEX email_login_codes_project_email_uidx RENAME TO email_login_codes_tenant_email_uidx;
ALTER INDEX email_login_codes_project_expires_idx RENAME TO email_login_codes_tenant_expires_idx;
ALTER TABLE email_login_codes RENAME COLUMN project_id TO tenant_id;

-- ── oauth_one_time_codes ───────────────────────────────────────────────
ALTER TABLE oauth_one_time_codes DROP CONSTRAINT oauth_one_time_codes_project_fk;
ALTER INDEX oauth_one_time_codes_project_code_uidx RENAME TO oauth_one_time_codes_tenant_code_uidx;
ALTER INDEX oauth_one_time_codes_project_expires_idx RENAME TO oauth_one_time_codes_tenant_expires_idx;
ALTER TABLE oauth_one_time_codes RENAME COLUMN project_id TO tenant_id;

-- ── identity_verifications ─────────────────────────────────────────────
ALTER TABLE identity_verifications DROP CONSTRAINT identity_verifications_project_fk;
ALTER INDEX idv_project_verification_uidx RENAME TO idv_tenant_verification_uidx;
ALTER INDEX idv_project_user_created_idx RENAME TO idv_user_created_idx;
ALTER TABLE identity_verifications RENAME COLUMN project_id TO tenant_id;

-- ── admin_help_requests ────────────────────────────────────────────────
ALTER TABLE admin_help_requests DROP CONSTRAINT admin_help_requests_project_fk;
ALTER INDEX admin_help_requests_project_status_idx RENAME TO admin_help_requests_status_idx;
ALTER INDEX admin_help_requests_project_email_idx RENAME TO admin_help_requests_email_idx;
ALTER TABLE admin_help_requests RENAME COLUMN project_id TO tenant_id;

-- ── login_challenges ───────────────────────────────────────────────────
ALTER TABLE login_challenges DROP CONSTRAINT login_challenges_project_fk;
ALTER INDEX lc_project_cid_uidx RENAME TO lc_tenant_cid_uidx;
ALTER INDEX lc_project_expires_idx RENAME TO lc_tenant_expires_idx;
ALTER TABLE login_challenges RENAME COLUMN project_id TO tenant_id;

-- ── recovery_codes ─────────────────────────────────────────────────────
ALTER TABLE recovery_codes DROP CONSTRAINT recovery_codes_project_fk;
ALTER INDEX rc_project_user_code_uidx RENAME TO rc_tenant_user_code_uidx;
ALTER TABLE recovery_codes RENAME COLUMN project_id TO tenant_id;

-- ── totp_secrets ───────────────────────────────────────────────────────
ALTER TABLE totp_secrets DROP CONSTRAINT totp_secrets_project_fk;
ALTER INDEX totp_project_user_idx RENAME TO totp_user_idx;
ALTER TABLE totp_secrets RENAME COLUMN project_id TO tenant_id;

-- ── passkey_challenges ─────────────────────────────────────────────────
ALTER TABLE passkey_challenges DROP CONSTRAINT passkey_challenges_project_fk;
ALTER INDEX pkc_project_idx RENAME TO pkc_tenant_idx;
ALTER INDEX pkc_project_expires_idx RENAME TO pkc_tenant_expires_idx;
ALTER TABLE passkey_challenges RENAME COLUMN project_id TO tenant_id;

-- ── passkeys ───────────────────────────────────────────────────────────
ALTER TABLE passkeys DROP CONSTRAINT passkeys_project_fk;
ALTER INDEX passkeys_project_credid_uidx RENAME TO passkeys_tenant_credid_uidx;
ALTER INDEX passkeys_project_user_idx RENAME TO passkeys_user_idx;
ALTER TABLE passkeys RENAME COLUMN project_id TO tenant_id;

-- ── qr_login_sessions ──────────────────────────────────────────────────
ALTER TABLE qr_login_sessions DROP CONSTRAINT qr_login_sessions_project_fk;
ALTER INDEX qr_project_sid_uidx RENAME TO qr_tenant_sid_uidx;
ALTER INDEX qr_project_expires_idx RENAME TO qr_tenant_expires_idx;
ALTER TABLE qr_login_sessions RENAME COLUMN project_id TO tenant_id;

-- ── user_invitations ───────────────────────────────────────────────────
ALTER TABLE user_invitations DROP CONSTRAINT user_invitations_project_fk;
ALTER INDEX inv_project_hash_uidx RENAME TO inv_tenant_hash_uidx;
ALTER INDEX inv_project_email_uidx RENAME TO inv_tenant_email_uidx;
ALTER INDEX inv_project_expires_idx RENAME TO inv_tenant_expires_idx;
ALTER TABLE user_invitations RENAME COLUMN project_id TO tenant_id;

-- ── audit_events ───────────────────────────────────────────────────────
ALTER TABLE audit_events DROP CONSTRAINT audit_events_project_fk;
ALTER INDEX audit_project_actor_time_idx RENAME TO audit_actor_time_idx;
ALTER INDEX audit_project_event_type_idx RENAME TO audit_event_type_idx;
ALTER TABLE audit_events RENAME COLUMN project_id TO tenant_id;

-- ── group_memberships ──────────────────────────────────────────────────
ALTER TABLE group_memberships DROP CONSTRAINT group_memberships_project_fk;
ALTER INDEX gm_project_user_idx RENAME TO gm_user_idx;
ALTER TABLE group_memberships RENAME COLUMN project_id TO tenant_id;

-- ── groups ─────────────────────────────────────────────────────────────
ALTER TABLE groups DROP CONSTRAINT groups_project_fk;
ALTER INDEX groups_project_name_uidx RENAME TO groups_tenant_name_uidx;
ALTER TABLE groups RENAME COLUMN project_id TO tenant_id;

-- ── oauth_identities ───────────────────────────────────────────────────
ALTER TABLE oauth_identities DROP CONSTRAINT oauth_identities_project_fk;
ALTER INDEX oi_project_provider_subject_uidx RENAME TO oi_tenant_provider_subject_uidx;
ALTER INDEX oi_project_user_idx RENAME TO oi_user_idx;
ALTER TABLE oauth_identities RENAME COLUMN project_id TO tenant_id;

-- ── email_change_tokens ────────────────────────────────────────────────
ALTER TABLE email_change_tokens DROP CONSTRAINT email_change_tokens_project_fk;
ALTER INDEX ect_project_hash_uidx RENAME TO ect_tenant_hash_uidx;
ALTER INDEX ect_project_expires_idx RENAME TO ect_tenant_expires_idx;
ALTER TABLE email_change_tokens RENAME COLUMN project_id TO tenant_id;

-- ── email_verification_tokens ──────────────────────────────────────────
ALTER TABLE email_verification_tokens DROP CONSTRAINT email_verification_tokens_project_fk;
ALTER INDEX evt_project_hash_uidx RENAME TO evt_tenant_hash_uidx;
ALTER INDEX evt_project_user_idx RENAME TO evt_user_idx;
ALTER INDEX evt_project_expires_idx RENAME TO evt_tenant_expires_idx;
ALTER TABLE email_verification_tokens RENAME COLUMN project_id TO tenant_id;

-- ── password_reset_tokens ──────────────────────────────────────────────
ALTER TABLE password_reset_tokens DROP CONSTRAINT password_reset_tokens_project_fk;
ALTER INDEX prt_project_hash_uidx RENAME TO prt_tenant_hash_uidx;
ALTER INDEX prt_project_user_idx RENAME TO prt_user_idx;
ALTER INDEX prt_project_expires_idx RENAME TO prt_tenant_expires_idx;
ALTER TABLE password_reset_tokens RENAME COLUMN project_id TO tenant_id;

-- ── sessions ───────────────────────────────────────────────────────────
ALTER TABLE sessions DROP CONSTRAINT sessions_project_fk;
ALTER INDEX sessions_project_sid_uidx RENAME TO sessions_tenant_sid_uidx;
ALTER INDEX sessions_project_user_idx RENAME TO sessions_tenant_user_idx;
ALTER TABLE sessions RENAME COLUMN project_id TO tenant_id;

-- ── refresh_tokens ─────────────────────────────────────────────────────
ALTER TABLE refresh_tokens DROP CONSTRAINT refresh_tokens_project_fk;
ALTER INDEX refresh_tokens_project_hash_uidx RENAME TO refresh_tokens_tenant_hash_uidx;
ALTER INDEX refresh_tokens_project_user_idx RENAME TO refresh_tokens_user_idx;
ALTER TABLE refresh_tokens RENAME COLUMN project_id TO tenant_id;

-- ── users ──────────────────────────────────────────────────────────────
ALTER TABLE users DROP CONSTRAINT users_project_fk;
ALTER INDEX users_project_email_uidx RENAME TO users_tenant_email_uidx;
ALTER INDEX users_project_status_idx RENAME TO users_tenant_status_idx;
ALTER TABLE users RENAME COLUMN project_id TO tenant_id;
