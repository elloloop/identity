-- 0033_add_directory_reader_credential_kind.up.sql
--
-- A directory_reader project credential authorizes one read-only RPC,
-- LookupUsers, against its own project. It is a new value of the existing
-- kind column, so only the CHECK constraint widens; no row changes.
ALTER TABLE project_credentials
    DROP CONSTRAINT project_credentials_kind_check;
ALTER TABLE project_credentials
    ADD CONSTRAINT project_credentials_kind_check
        CHECK (kind IN ('publishable','secret','mtls','directory_reader'));
