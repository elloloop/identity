DROP INDEX IF EXISTS users_project_pending_deletion_idx;

-- Restore the pre-0025 status CHECK. Any pending_deletion / (unwidened)
-- pending_parental_consent rows would violate it; a deployment rolling back
-- must resolve those rows first.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active', 'invited', 'deactivated', 'suspended'));

ALTER TABLE users DROP COLUMN IF EXISTS deletion_scheduled_at_ms;
