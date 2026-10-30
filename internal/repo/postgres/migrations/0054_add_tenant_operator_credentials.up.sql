-- 0054_add_tenant_operator_credentials.up.sql
--
-- A tenant_operator credential authorizes the tenant operations on its own
-- project's tenants in place of the admin secret. It is a new value of the
-- existing kind column, so only its CHECK widens; replacing it holds ACCESS
-- EXCLUSIVE on project_credentials while it validates that small table.
SET LOCAL lock_timeout = '10s';

ALTER TABLE project_credentials DROP CONSTRAINT project_credentials_kind_check;
ALTER TABLE project_credentials ADD CONSTRAINT project_credentials_kind_check
    CHECK (kind IN ('publishable','secret','mtls','directory_reader','teammate_key_manager','tenant_operator'));
