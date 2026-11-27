-- 0068_add_managed_accounts.up.sql
--
-- Tenant-managed accounts. users.managed_by_tenant_id names the tenant that
-- manages an account ('' for a personal one); set_up_at_ms is when it was
-- first set up from its link (0 until then); setup_epoch numbers its set-up
-- links, so only the current one sets it up. tenant_invitations gains the
-- set-up link's account (user_id), where the link was sent
-- (delivery_email; email holds the account's address) and the epoch it was
-- issued for. Every column has a constant default, so adding it rewrites
-- nothing and existing rows read as personal accounts and ordinary
-- invitations.
--
-- The index serves "the pending set-up links of this account", which every
-- managed write revokes before issuing a new one. tenant_invitations has no
-- RLS. CREATE INDEX takes SHARE on tenant_invitations, blocking invitation
-- writes, not reads, while it builds, as 0058's did; on a large table build
-- it CONCURRENTLY first (docs/UPGRADE.md) and this statement finds it.
-- lock_timeout bounds the wait for each lock (on timeout: confirm the
-- columns are absent, then `identity migrate force 67` and
-- `identity migrate`).
SET LOCAL lock_timeout = '10s';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS managed_by_tenant_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS set_up_at_ms BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS setup_epoch BIGINT NOT NULL DEFAULT 0;

ALTER TABLE tenant_invitations
    ADD COLUMN IF NOT EXISTS delivery_email TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS user_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS setup_epoch BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS tenant_invitations_pending_user_idx
    ON tenant_invitations (project_id, user_id)
    WHERE user_id <> '' AND status = 'pending';
