-- managed_child_reader credentials cannot survive the narrower CHECK.
-- Rollback deletes those credentials and disables the live authorization access they grant.
SET LOCAL lock_timeout = '10s';
DELETE FROM project_credentials WHERE kind = 'managed_child_reader';
ALTER TABLE project_credentials DROP CONSTRAINT project_credentials_kind_check;
ALTER TABLE project_credentials ADD CONSTRAINT project_credentials_kind_check
  CHECK (kind IN ('publishable','secret','mtls','directory_reader','teammate_key_manager','tenant_operator'));
