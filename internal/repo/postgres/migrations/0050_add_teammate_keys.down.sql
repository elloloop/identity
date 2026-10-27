-- 0050_add_teammate_keys.down.sql
--
-- Teammate key manager credentials cannot survive the narrower constraint,
-- so the rollback deletes them with the keys: rolling back removes the
-- feature they authorize.
SET LOCAL lock_timeout = '10s';

DROP TABLE teammate_key_challenges;
DROP TABLE teammate_keys;
DELETE FROM project_credentials WHERE kind = 'teammate_key_manager';
ALTER TABLE project_credentials DROP CONSTRAINT project_credentials_kind_check;
ALTER TABLE project_credentials ADD CONSTRAINT project_credentials_kind_check
    CHECK (kind IN ('publishable','secret','mtls','directory_reader'));
