-- 0034_add_user_email_fold.down.sql
--
-- Restores the locale lower() unique index. Addresses that 0034 let coexist
-- because they differ only in non-ASCII case ("é" and "É") collide under it
-- wherever the database locale folds them; the build then fails and this
-- file rolls back unapplied until those duplicates are resolved.
CREATE UNIQUE INDEX users_project_email_partial_uidx
    ON users (project_id, lower(email))
    WHERE email <> '';
DROP INDEX users_project_email_fold_uidx;
ALTER TABLE users DROP COLUMN email_fold;
