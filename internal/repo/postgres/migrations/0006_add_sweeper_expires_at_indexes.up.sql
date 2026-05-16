-- 0006_add_sweeper_expires_at_indexes.up.sql
--
-- Indexes that the background garbage-collection sweeper (issue #94)
-- relies on. Each sweeper batch runs
--
--     DELETE FROM <table>
--      WHERE id IN (SELECT id FROM <table>
--                    WHERE tenant_id = $1 AND expires_at_ms < $2
--                    ORDER BY expires_at_ms ASC
--                    LIMIT $3)
--
-- which without an index on (tenant_id, expires_at_ms) walks the
-- whole partition every tick. At million-user scale these five
-- ephemeral tables grow fastest, so the cost of the index pays for
-- itself within the first sweep cycle.

CREATE INDEX IF NOT EXISTS pkc_tenant_expires_idx
    ON passkey_challenges (tenant_id, expires_at_ms);
CREATE INDEX IF NOT EXISTS evt_tenant_expires_idx
    ON email_verification_tokens (tenant_id, expires_at_ms);
CREATE INDEX IF NOT EXISTS prt_tenant_expires_idx
    ON password_reset_tokens (tenant_id, expires_at_ms);
CREATE INDEX IF NOT EXISTS ect_tenant_expires_idx
    ON email_change_tokens (tenant_id, expires_at_ms);
CREATE INDEX IF NOT EXISTS lc_tenant_expires_idx
    ON login_challenges (tenant_id, expires_at_ms);
