-- 0012_add_qr_invitation_sweeper_indexes.up.sql
--
-- qr_login_sessions and user_invitations were the two ephemeral,
-- expires_at-bearing tables with no background GC sweeper (issue #187),
-- so they had no (tenant_id, expires_at_ms) index either. Now that the
-- sweeper reaps them, add the same B-tree the other ephemeral tables got
-- in 0006 so the batched delete stays off a full-partition scan.

CREATE INDEX IF NOT EXISTS qr_tenant_expires_idx
    ON qr_login_sessions (tenant_id, expires_at_ms);
CREATE INDEX IF NOT EXISTS inv_tenant_expires_idx
    ON user_invitations (tenant_id, expires_at_ms);
