-- 0050_domain_join.up.sql
--
-- A tenant may let the people whose verified email is on one of its verified
-- domains join it themselves (JoinTenantByDomain), domain by domain, and a
-- tenant admin turns that on with SetDomainJoin. allow_join records the
-- choice. It is off on every existing row and on every new one, so no
-- tenant admits anyone it did not before. It governs only joining by
-- request: a signup on a verified domain joins as auto-formation always did
-- (0013, 0045), and turning it off ends no membership.
--
-- The agent-governance trigger on domains (0046) fires on a change of
-- status, tenant_id or domain only, so writing allow_join revokes nothing.
--
-- Locks: ADD COLUMN with a constant default rewrites nothing, but takes an
-- ACCESS EXCLUSIVE lock on domains, blocking reads and writes to it, signup's
-- auto-formation included, for as long as the catalog change takes.
-- lock_timeout bounds only the wait to acquire it, as in 0034-0049. On a
-- timeout the file rolls back and version 50 is left dirty:
-- `identity migrate force 49`, then `identity migrate` again.
SET LOCAL lock_timeout = '10s';

ALTER TABLE domains ADD COLUMN IF NOT EXISTS allow_join BOOLEAN NOT NULL DEFAULT false;
