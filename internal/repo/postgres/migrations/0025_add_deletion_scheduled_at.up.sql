-- Self-service account deletion (GDPR Art 17). An authenticated user can
-- schedule deletion of their OWN account: it moves to status
-- 'pending_deletion' and is retained until deletion_scheduled_at_ms, when the
-- background sweeper hard-deletes it. A login during the grace window (or an
-- explicit cancel) restores the account. 0 = not pending deletion.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS deletion_scheduled_at_ms BIGINT NOT NULL DEFAULT 0;

-- Widen the status CHECK to admit the two statuses added since 0001_init:
-- 'pending_parental_consent' (age-gating, #256) and 'pending_deletion' (this
-- migration). The original 0001 constraint listed only the first four values
-- and was never widened when pending_parental_consent landed, so this also
-- closes that latent gap. Storing statuses as TEXT+CHECK (not a PG enum) is the
-- repo's deliberate choice precisely so widening is a one-line swap.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN (
        'active', 'invited', 'deactivated', 'suspended',
        'pending_parental_consent', 'pending_deletion'
    ));

-- Backing index for the sweeper's due-accounts scan
-- (ListUsersPendingDeletionBefore): a partial index over just the
-- pending_deletion rows keyed on the scheduled instant keeps the periodic
-- query off a full users scan.
CREATE INDEX IF NOT EXISTS users_project_pending_deletion_idx
    ON users (project_id, deletion_scheduled_at_ms)
    WHERE status = 'pending_deletion';
