-- 0034_add_user_email_fold.up.sql
--
-- users.email_fold is the key account emails are matched and kept unique by:
-- the address with its ASCII letters lowered and every other character kept
-- (service.FoldEmail, which the SQLite and memory drivers apply too).
-- lower() under the "C" collation folds exactly ASCII whatever the database's
-- locale. The database-default lower() folded by locale instead — most of
-- Unicode under en_US.UTF-8, ASCII only under C — so the same addresses
-- compared differently from one deployment to another and from the service.
--
-- It is a stored column rather than an expression index because of FORCE
-- ROW LEVEL SECURITY (0016): a predicate is evaluated ahead of the row
-- policy, and so can be an index condition, only if every function in it is
-- leakproof. lower() is not, so `lower(email) = lower($2)` ran as a filter
-- over every row of the project. Text `=` on email_fold is leakproof.
--
-- Adding a stored generated column rewrites `users` under an ACCESS
-- EXCLUSIVE lock, for a time proportional to the table's size. Neither the
-- rewrite nor the index build is subject to RLS, so unlike 0028 and 0031
-- nothing here has to suspend it.
ALTER TABLE users
    ADD COLUMN email_fold TEXT COLLATE "C"
        GENERATED ALWAYS AS (lower(email COLLATE "C")) STORED;

-- Uniqueness follows the same rule as lookup, so it replaces
-- users_project_email_partial_uidx. Addresses equal under the ASCII fold
-- were equal under the old lower() in every locale that lowers ASCII letters
-- to ASCII, so existing rows satisfy it; under a Turkic locale ("I" lowers
-- to a dotless "ı") a pair can collide, and the build then fails and this
-- file rolls back unapplied. Built before the drop so uniqueness is never
-- unenforced.
CREATE UNIQUE INDEX users_project_email_fold_uidx
    ON users (project_id, email_fold)
    WHERE email <> '';
DROP INDEX users_project_email_partial_uidx;
