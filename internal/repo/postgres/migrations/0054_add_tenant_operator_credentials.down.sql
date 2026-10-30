-- 0054_add_tenant_operator_credentials.down.sql
--
-- Tenant operator credentials cannot survive the narrower constraint, so the
-- rollback deletes them: rolling back removes what they authorize, and a
-- service that held one needs the admin secret again.
SET LOCAL lock_timeout = '10s';

DELETE FROM project_credentials WHERE kind = 'tenant_operator';
ALTER TABLE project_credentials DROP CONSTRAINT project_credentials_kind_check;
ALTER TABLE project_credentials ADD CONSTRAINT project_credentials_kind_check
    CHECK (kind IN ('publishable','secret','mtls','directory_reader','teammate_key_manager'));
