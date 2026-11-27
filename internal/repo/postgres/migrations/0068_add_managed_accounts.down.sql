-- 0068_add_managed_accounts.down.sql
--
-- Do not roll back past this migration once managed accounts exist: it turns
-- every managed account into a personal one that nothing then restricts, and
-- every pending set-up link into an ordinary invitation to the account's
-- address (docs/UPGRADE.md).
SET LOCAL lock_timeout = '10s';

DROP INDEX IF EXISTS tenant_invitations_pending_user_idx;

ALTER TABLE tenant_invitations
    DROP COLUMN IF EXISTS setup_epoch,
    DROP COLUMN IF EXISTS user_id,
    DROP COLUMN IF EXISTS delivery_email;

ALTER TABLE users
    DROP COLUMN IF EXISTS setup_epoch,
    DROP COLUMN IF EXISTS set_up_at_ms,
    DROP COLUMN IF EXISTS managed_by_tenant_id;
