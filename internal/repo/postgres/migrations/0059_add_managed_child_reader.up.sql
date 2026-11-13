SET LOCAL lock_timeout = '10s';
ALTER TABLE project_credentials DROP CONSTRAINT project_credentials_kind_check;
ALTER TABLE project_credentials ADD CONSTRAINT project_credentials_kind_check
  CHECK (kind IN ('publishable','secret','mtls','directory_reader','teammate_key_manager','tenant_operator','managed_child_reader'));
