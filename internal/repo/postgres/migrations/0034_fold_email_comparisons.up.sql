-- 0034_fold_email_comparisons.up.sql
--
-- Account emails are compared under one storage rule, service.FoldEmail:
-- ASCII letters lowered, every other character kept. lower() under the "C"
-- collation computes exactly that whatever the database's locale. The
-- database-default lower() folded by locale instead — most of Unicode under
-- en_US.UTF-8, ASCII only under C — so the same addresses compared
-- differently from one deployment to another and from the SQLite and memory
-- drivers. The service canonicalizes an address before it reaches a store;
-- this rule only makes the stores agree on what they are given.
--
-- users.email_fold is a stored column rather than an expression index because
-- of FORCE ROW LEVEL SECURITY (0016): a predicate is evaluated ahead of the
-- row policy, and so can be an index condition, only if every function in it
-- is leakproof. lower() is not, so `lower(email) = lower($2)` ran as a filter
-- over every row of the project. Text `=` on email_fold is leakproof.
--
-- Adding a stored generated column rewrites `users` under an ACCESS EXCLUSIVE
-- lock, for a time proportional to the table's size, and the unique index is
-- then built in the same transaction; sign-in, refresh and SCIM wait for both.
-- lock_timeout bounds only the wait to ACQUIRE that lock: queued behind a
-- long-running transaction, the ALTER would otherwise stall every later query
-- on `users` until it got the lock. On timeout — or on any failure below —
-- the file's changes roll back, but the migration runner leaves schema
-- version 34 marked dirty and refuses every later run: confirm email_fold is
-- absent, then `identity migrate force 33` and `identity migrate` again
-- (docs/UPGRADE.md). It does not bound the rewrite itself — size the
-- maintenance window from the table. The IF [NOT] EXISTS
-- guards let an operator run these statements by hand in that window (or
-- pre-build the index with CREATE UNIQUE INDEX CONCURRENTLY once the column
-- exists) and have the migration no-op over them. Neither the rewrite nor the
-- index builds are subject to RLS, so unlike 0028 and 0031 nothing here has to
-- suspend it.
SET LOCAL lock_timeout = '10s';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_fold TEXT COLLATE "C"
        GENERATED ALWAYS AS (lower(email COLLATE "C")) STORED;

-- Uniqueness follows the same rule as lookup, so it replaces
-- users_project_email_partial_uidx. Addresses equal under the ASCII fold
-- were equal under the old lower() in every locale that lowers ASCII letters
-- to ASCII, so existing rows satisfy it; under a Turkic locale ("I" lowers
-- to a dotless "ı") a pair can collide, and the build then fails and this
-- file rolls back, leaving version 34 dirty as above. Built before the drop so uniqueness is never
-- unenforced.
CREATE UNIQUE INDEX IF NOT EXISTS users_project_email_fold_uidx
    ON users (project_id, email_fold)
    WHERE email <> '';
DROP INDEX IF EXISTS users_project_email_partial_uidx;

-- Pending invitations stored before the service canonicalized carry the
-- address as typed (trimmed and lower-cased). Rewrite them in the canonical
-- form the service now stores (service.CanonicalizeEmail) so that the fold of
-- a pending invitation names its mailbox and the revoke-then-insert, which
-- compares folds, finds it. For an all-ASCII address the canonical form is
-- exactly: lower-cased; one trailing dot dropped from the domain;
-- googlemail.com read as gmail.com; the local part cut at its first "+"; and,
-- at gmail.com, its dots removed. Non-ASCII addresses (whose canonical form
-- punycodes the domain) are left as they are. Where several pending
-- invitations canonicalize to one mailbox, all but the newest are revoked
-- first — what creating the newest would have done.
WITH parts AS (
    SELECT id, project_id, tenant_id, created_at_ms,
           substring(lower(email COLLATE "C") FROM '^(.*)@') AS local_part,
           regexp_replace(substring(lower(email COLLATE "C") FROM '@([^@]*)$'), '\.$', '') AS raw_domain
    FROM tenant_invitations
    WHERE status = 'pending' AND email ~ '^[!-~]+@[!-~]+$'
), domains AS (
    SELECT *, CASE WHEN raw_domain = 'googlemail.com' THEN 'gmail.com' ELSE raw_domain END AS domain
    FROM parts
), canonical AS (
    SELECT id, project_id, tenant_id, created_at_ms,
           CASE WHEN domain = 'gmail.com' THEN replace(split_part(local_part, '+', 1), '.', '')
                ELSE split_part(local_part, '+', 1)
           END || '@' || domain AS email
    FROM domains
), ranked AS (
    SELECT id, email,
           row_number() OVER (PARTITION BY project_id, tenant_id, email
                              ORDER BY created_at_ms DESC, id DESC) AS newest_first
    FROM canonical
), superseded AS (
    UPDATE tenant_invitations t SET status = 'revoked'
    FROM ranked r
    WHERE t.id = r.id AND r.newest_first > 1
    RETURNING t.id
)
UPDATE tenant_invitations t SET email = r.email
FROM ranked r
WHERE t.id = r.id AND r.newest_first = 1 AND t.email <> r.email;

-- The one-open-invite index follows the same rule as the revoke-then-insert
-- that enforces it. tenant_invitations has no RLS, so an expression index is
-- usable here.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_invitations_open_email_fold_uidx
    ON tenant_invitations (project_id, tenant_id, lower(email COLLATE "C"))
    WHERE status = 'pending';
DROP INDEX IF EXISTS tenant_invitations_open_email_uidx;
