-- 0256_add_date_of_birth.down.sql
ALTER TABLE users
    DROP COLUMN date_of_birth_ms;
