-- 0035_add_user_account_address.down.sql

DROP INDEX IF EXISTS users_project_account_address_uidx;
ALTER TABLE users
    DROP COLUMN IF EXISTS account_address;
