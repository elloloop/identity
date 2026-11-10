-- 0058_add_tenant_invitations_pending_email_idx.up.sql
--
-- A sign-up in an invite-only project looks for a pending invitation to the
-- address across every tenant of the project. The one-open-invite index leads
-- with tenant_id, so that lookup would scan every pending invitation of the
-- project; this index serves it. tenant_invitations has no RLS, so the
-- expression index is usable (0034). CREATE INDEX takes SHARE on
-- tenant_invitations, blocking invitation writes, not reads, while it builds;
-- lock_timeout bounds the wait to acquire it.
SET LOCAL lock_timeout = '10s';

CREATE INDEX IF NOT EXISTS tenant_invitations_pending_email_idx
    ON tenant_invitations (project_id, lower(email COLLATE "C"))
    WHERE status = 'pending';
