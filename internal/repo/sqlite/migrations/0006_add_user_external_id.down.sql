DROP INDEX IF EXISTS users_project_created_id_idx;

DROP INDEX IF EXISTS users_project_external_id_uidx;

ALTER TABLE users
    DROP COLUMN external_id;
