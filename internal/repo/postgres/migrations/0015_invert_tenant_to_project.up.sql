-- 0015_invert_tenant_to_project.up.sql
--
-- Invert the data-plane storage cardinality from the legacy tenant-shard
-- model to the Project model (ADR-0002, docs/adr/0002-project-is-the-
-- isolation-shard.md). Every kept auth/data-plane table's leading
-- `tenant_id` column is renamed to `project_id`, its uniqueness is
-- re-scoped to `(project_id, …)`, and a FOREIGN KEY to projects(id) is
-- added so a data-plane row can only exist under a real control-plane
-- Project. The project (migration 0013) is now the isolation shard; the
-- mandatory `WHERE project_id = $1` predicate is injected at the
-- RepositoryForProject boundary (internal/repo/postgres, internal/service).
--
-- BREAKING SCHEMA RESET (pre-v1.0 → v1.0): identity is pre-1.0 OSS with no
-- production data on the legacy model, so this is a clean column rename, not
-- an expand-backfill-contract. `ALTER TABLE … RENAME COLUMN` preserves the
-- existing NOT NULL and (because Postgres tracks index columns by identity,
-- not name) leaves every existing index functioning against the renamed
-- column; only the index *names* are updated to the `*_project_*` convention
-- via ALTER INDEX … RENAME. On empty data-plane tables the new FK to
-- projects(id) is trivially satisfied. Operators migrating real legacy data
-- run a separate one-off data-migration script (a deliberate FOLLOW-UP, out
-- of scope here) before applying this.
--
-- NOT in this migration (deliberate v1.1 follow-up): Postgres Row-Level
-- Security. RLS is defense-in-depth on top of the boundary predicate and
-- needs per-transaction GUC plumbing with pgxpool; it lands separately.
-- TODO(v1.1): RLS defense-in-depth — attach per-table policies here
-- (USING (project_id = current_setting('identity.project_id'))) once the
-- pgxpool per-acquire SET LOCAL plumbing is in place.
--
-- The logical-tenant `tenant_id` columns on the governance tables added in
-- 0013 (domains, login_policies, tenant_memberships, tenant_invitations)
-- reference tenants(id), NOT a storage shard, and are intentionally left
-- untouched.

-- ── users ──────────────────────────────────────────────────────────────
ALTER TABLE users RENAME COLUMN tenant_id TO project_id;
ALTER INDEX users_tenant_email_uidx RENAME TO users_project_email_uidx;
ALTER INDEX users_tenant_status_idx RENAME TO users_project_status_idx;
ALTER TABLE users
    ADD CONSTRAINT users_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── refresh_tokens ─────────────────────────────────────────────────────
ALTER TABLE refresh_tokens RENAME COLUMN tenant_id TO project_id;
ALTER INDEX refresh_tokens_tenant_hash_uidx RENAME TO refresh_tokens_project_hash_uidx;
ALTER INDEX refresh_tokens_user_idx RENAME TO refresh_tokens_project_user_idx;
ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── sessions (reshaped in 0008) ────────────────────────────────────────
ALTER TABLE sessions RENAME COLUMN tenant_id TO project_id;
ALTER INDEX sessions_tenant_sid_uidx RENAME TO sessions_project_sid_uidx;
ALTER INDEX sessions_tenant_user_idx RENAME TO sessions_project_user_idx;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── password_reset_tokens ──────────────────────────────────────────────
ALTER TABLE password_reset_tokens RENAME COLUMN tenant_id TO project_id;
ALTER INDEX prt_tenant_hash_uidx RENAME TO prt_project_hash_uidx;
ALTER INDEX prt_user_idx RENAME TO prt_project_user_idx;
ALTER INDEX prt_tenant_expires_idx RENAME TO prt_project_expires_idx;
ALTER TABLE password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── email_verification_tokens ──────────────────────────────────────────
ALTER TABLE email_verification_tokens RENAME COLUMN tenant_id TO project_id;
ALTER INDEX evt_tenant_hash_uidx RENAME TO evt_project_hash_uidx;
ALTER INDEX evt_user_idx RENAME TO evt_project_user_idx;
ALTER INDEX evt_tenant_expires_idx RENAME TO evt_project_expires_idx;
ALTER TABLE email_verification_tokens
    ADD CONSTRAINT email_verification_tokens_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── email_change_tokens ────────────────────────────────────────────────
ALTER TABLE email_change_tokens RENAME COLUMN tenant_id TO project_id;
ALTER INDEX ect_tenant_hash_uidx RENAME TO ect_project_hash_uidx;
ALTER INDEX ect_tenant_expires_idx RENAME TO ect_project_expires_idx;
ALTER TABLE email_change_tokens
    ADD CONSTRAINT email_change_tokens_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── oauth_identities ───────────────────────────────────────────────────
ALTER TABLE oauth_identities RENAME COLUMN tenant_id TO project_id;
ALTER INDEX oi_tenant_provider_subject_uidx RENAME TO oi_project_provider_subject_uidx;
ALTER INDEX oi_user_idx RENAME TO oi_project_user_idx;
ALTER TABLE oauth_identities
    ADD CONSTRAINT oauth_identities_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── groups ─────────────────────────────────────────────────────────────
ALTER TABLE groups RENAME COLUMN tenant_id TO project_id;
ALTER INDEX groups_tenant_name_uidx RENAME TO groups_project_name_uidx;
ALTER TABLE groups
    ADD CONSTRAINT groups_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── group_memberships (project_id is part of the composite PK) ──────────
ALTER TABLE group_memberships RENAME COLUMN tenant_id TO project_id;
ALTER INDEX gm_user_idx RENAME TO gm_project_user_idx;
ALTER TABLE group_memberships
    ADD CONSTRAINT group_memberships_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── audit_events ───────────────────────────────────────────────────────
ALTER TABLE audit_events RENAME COLUMN tenant_id TO project_id;
ALTER INDEX audit_actor_time_idx RENAME TO audit_project_actor_time_idx;
ALTER INDEX audit_event_type_idx RENAME TO audit_project_event_type_idx;
ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── user_invitations ───────────────────────────────────────────────────
ALTER TABLE user_invitations RENAME COLUMN tenant_id TO project_id;
ALTER INDEX inv_tenant_hash_uidx RENAME TO inv_project_hash_uidx;
ALTER INDEX inv_tenant_email_uidx RENAME TO inv_project_email_uidx;
ALTER INDEX inv_tenant_expires_idx RENAME TO inv_project_expires_idx;
ALTER TABLE user_invitations
    ADD CONSTRAINT user_invitations_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── qr_login_sessions ──────────────────────────────────────────────────
ALTER TABLE qr_login_sessions RENAME COLUMN tenant_id TO project_id;
ALTER INDEX qr_tenant_sid_uidx RENAME TO qr_project_sid_uidx;
ALTER INDEX qr_tenant_expires_idx RENAME TO qr_project_expires_idx;
ALTER TABLE qr_login_sessions
    ADD CONSTRAINT qr_login_sessions_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── passkeys ───────────────────────────────────────────────────────────
ALTER TABLE passkeys RENAME COLUMN tenant_id TO project_id;
ALTER INDEX passkeys_tenant_credid_uidx RENAME TO passkeys_project_credid_uidx;
ALTER INDEX passkeys_user_idx RENAME TO passkeys_project_user_idx;
ALTER TABLE passkeys
    ADD CONSTRAINT passkeys_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── passkey_challenges ─────────────────────────────────────────────────
ALTER TABLE passkey_challenges RENAME COLUMN tenant_id TO project_id;
ALTER INDEX pkc_tenant_idx RENAME TO pkc_project_idx;
ALTER INDEX pkc_tenant_expires_idx RENAME TO pkc_project_expires_idx;
ALTER TABLE passkey_challenges
    ADD CONSTRAINT passkey_challenges_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── totp_secrets ───────────────────────────────────────────────────────
ALTER TABLE totp_secrets RENAME COLUMN tenant_id TO project_id;
ALTER INDEX totp_user_idx RENAME TO totp_project_user_idx;
ALTER TABLE totp_secrets
    ADD CONSTRAINT totp_secrets_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── recovery_codes ─────────────────────────────────────────────────────
ALTER TABLE recovery_codes RENAME COLUMN tenant_id TO project_id;
ALTER INDEX rc_tenant_user_code_uidx RENAME TO rc_project_user_code_uidx;
ALTER TABLE recovery_codes
    ADD CONSTRAINT recovery_codes_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── login_challenges ───────────────────────────────────────────────────
ALTER TABLE login_challenges RENAME COLUMN tenant_id TO project_id;
ALTER INDEX lc_tenant_cid_uidx RENAME TO lc_project_cid_uidx;
ALTER INDEX lc_tenant_expires_idx RENAME TO lc_project_expires_idx;
ALTER TABLE login_challenges
    ADD CONSTRAINT login_challenges_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── admin_help_requests (added in 0002) ────────────────────────────────
ALTER TABLE admin_help_requests RENAME COLUMN tenant_id TO project_id;
ALTER INDEX admin_help_requests_status_idx RENAME TO admin_help_requests_project_status_idx;
ALTER INDEX admin_help_requests_email_idx RENAME TO admin_help_requests_project_email_idx;
ALTER TABLE admin_help_requests
    ADD CONSTRAINT admin_help_requests_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── identity_verifications (added in 0003) ─────────────────────────────
ALTER TABLE identity_verifications RENAME COLUMN tenant_id TO project_id;
ALTER INDEX idv_tenant_verification_uidx RENAME TO idv_project_verification_uidx;
ALTER INDEX idv_user_created_idx RENAME TO idv_project_user_created_idx;
ALTER TABLE identity_verifications
    ADD CONSTRAINT identity_verifications_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── oauth_one_time_codes (added in 0009) ───────────────────────────────
ALTER TABLE oauth_one_time_codes RENAME COLUMN tenant_id TO project_id;
ALTER INDEX oauth_one_time_codes_tenant_code_uidx RENAME TO oauth_one_time_codes_project_code_uidx;
ALTER INDEX oauth_one_time_codes_tenant_expires_idx RENAME TO oauth_one_time_codes_project_expires_idx;
ALTER TABLE oauth_one_time_codes
    ADD CONSTRAINT oauth_one_time_codes_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── email_login_codes (added in 0010) ──────────────────────────────────
ALTER TABLE email_login_codes RENAME COLUMN tenant_id TO project_id;
ALTER INDEX email_login_codes_tenant_email_uidx RENAME TO email_login_codes_project_email_uidx;
ALTER INDEX email_login_codes_tenant_expires_idx RENAME TO email_login_codes_project_expires_idx;
ALTER TABLE email_login_codes
    ADD CONSTRAINT email_login_codes_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── magic_link_tokens (added in 0010) ──────────────────────────────────
ALTER TABLE magic_link_tokens RENAME COLUMN tenant_id TO project_id;
ALTER INDEX magic_link_tokens_tenant_token_uidx RENAME TO magic_link_tokens_project_token_uidx;
ALTER INDEX magic_link_tokens_tenant_expires_idx RENAME TO magic_link_tokens_project_expires_idx;
ALTER TABLE magic_link_tokens
    ADD CONSTRAINT magic_link_tokens_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── phone_verification_codes (added in 0011) ───────────────────────────
ALTER TABLE phone_verification_codes RENAME COLUMN tenant_id TO project_id;
ALTER INDEX phone_verification_codes_tenant_user_uidx RENAME TO phone_verification_codes_project_user_uidx;
ALTER INDEX phone_verification_codes_tenant_expires_idx RENAME TO phone_verification_codes_project_expires_idx;
ALTER TABLE phone_verification_codes
    ADD CONSTRAINT phone_verification_codes_project_fk
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;
