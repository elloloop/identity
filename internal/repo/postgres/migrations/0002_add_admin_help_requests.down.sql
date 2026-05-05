DROP TABLE IF EXISTS admin_help_requests;

ALTER TABLE groups
    DROP COLUMN IF EXISTS created_by;
