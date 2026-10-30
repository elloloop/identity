-- 0055_add_hire_grants.down.sql
--
-- Drops hire grants and the grant and owner of each teammate key. Keys the
-- up migration revoked stay revoked, and a key revoked with a deadline still
-- ahead keeps it, which an older release reads as already revoked.
SET LOCAL lock_timeout = '10s';

ALTER TABLE teammate_keys
    DROP CONSTRAINT teammate_keys_granted,
    DROP COLUMN owner_user_id,
    DROP COLUMN grant_id;
DROP TABLE hire_grants;
