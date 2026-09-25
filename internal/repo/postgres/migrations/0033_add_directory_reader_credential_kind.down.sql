-- 0033_add_directory_reader_credential_kind.down.sql
--
-- Directory credentials cannot survive the narrower constraint, so the
-- rollback deletes them: rolling back removes the feature they authorize.
DELETE FROM project_credentials WHERE kind = 'directory_reader';
ALTER TABLE project_credentials
    DROP CONSTRAINT project_credentials_kind_check;
ALTER TABLE project_credentials
    ADD CONSTRAINT project_credentials_kind_check
        CHECK (kind IN ('publishable','secret','mtls'));
