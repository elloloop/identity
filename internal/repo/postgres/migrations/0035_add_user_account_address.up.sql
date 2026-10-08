-- 0035_add_user_account_address.up.sql
--
-- The account address a project issues on its own domain (config_json
-- accounts.domain): <username>@<domain> for a username account, the email
-- with '@' written as "-at-" for an email account. Empty on every account of
-- a project that issues none. The partial unique index covers only non-empty
-- addresses (matching the email and username indexes), so the default ''
-- rows never collide. Comparisons are exact: the service writes addresses
-- lower-cased.
--
-- A constant default makes the ADD COLUMN a catalog-only change (no table
-- rewrite). The index build holds a SHARE lock on `users` for a time
-- proportional to the table's size, blocking writes but not reads; every
-- row is '' at that point, so the partial index has nothing to index and the
-- build is a single scan. lock_timeout bounds the wait to acquire either
-- lock, as in 0034: on timeout the file rolls back and version 35 is left
-- dirty — confirm account_address is absent, then `identity migrate force
-- 34` and `identity migrate` again. The IF [NOT] EXISTS guards let an
-- operator pre-build the index with CREATE UNIQUE INDEX CONCURRENTLY.
SET LOCAL lock_timeout = '10s';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS account_address TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS users_project_account_address_uidx
    ON users (project_id, account_address)
    WHERE account_address <> '';
