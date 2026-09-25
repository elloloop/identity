-- 0034_fold_email_comparisons.down.sql
--
-- Restores the locale lower() unique indexes. Addresses that 0034 let coexist
-- because they differ only in non-ASCII case ("é" and "É") collide under them
-- wherever the database locale folds them; the build then fails and this
-- file rolls back with 0034 still in place, while the runner marks version 33
-- dirty (`identity migrate force 34` records the truth), until those
-- duplicates are resolved (docs/UPGRADE.md). lock_timeout as in the up migration.
SET LOCAL lock_timeout = '10s';

CREATE UNIQUE INDEX IF NOT EXISTS tenant_invitations_open_email_uidx
    ON tenant_invitations (project_id, tenant_id, lower(email))
    WHERE status = 'pending';
DROP INDEX IF EXISTS tenant_invitations_open_email_fold_uidx;

CREATE UNIQUE INDEX IF NOT EXISTS users_project_email_partial_uidx
    ON users (project_id, lower(email))
    WHERE email <> '';
DROP INDEX IF EXISTS users_project_email_fold_uidx;
ALTER TABLE users DROP COLUMN IF EXISTS email_fold;
