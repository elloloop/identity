-- 0053_suspend_tenant_members.up.sql
--
-- A tenant owner or admin can suspend a member (SuspendTenantMember). The
-- membership stays, with its role and source, at status 'suspended'. Every
-- read that lets a member act in a tenant asks for 'active', so it leaves a
-- suspended one out. The status CHECK is widened to admit it, NOT VALID:
-- every existing row satisfies the wider constraint, so the scan is skipped
-- and every later write is checked.
--
-- 0047's trigger ends a domain membership when the email leaves the domain,
-- and a person whose domain membership ended may join again by domain once
-- the email is back (JoinTenantByDomain). Ending a suspended one would let
-- its holder shed the suspension that way, so the trigger now leaves a
-- suspended row alone, and RestoreTenantMember applies the domain rule when
-- it lifts the suspension.
--
-- Locks: the ALTERs take an ACCESS EXCLUSIVE lock on tenant_memberships
-- that the transaction holds until it commits, so membership reads and
-- writes, sign-in's tenant reads included, wait for the rest of the file,
-- which is catalog changes only. Replacing the function takes no lock on
-- users. lock_timeout bounds the wait to acquire the lock, as in 0034-0052.
-- On a timeout the file rolls back and version 53 is left dirty:
-- `identity migrate force 52`, then `identity migrate` again.
SET LOCAL lock_timeout = '10s';

ALTER TABLE tenant_memberships DROP CONSTRAINT IF EXISTS tenant_memberships_status_check;
ALTER TABLE tenant_memberships
    ADD CONSTRAINT tenant_memberships_status_check
    CHECK (status IN ('active', 'pending', 'inactive', 'suspended')) NOT VALID;

CREATE OR REPLACE FUNCTION end_domain_memberships_off_domain() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE tenant_memberships m
    SET status = 'inactive',
        updated_at_ms = (EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT
  WHERE m.project_id = NEW.project_id AND m.user_id = NEW.id
    AND m.source = 'domain' AND m.status NOT IN ('inactive', 'suspended')
    AND NOT EXISTS (
         SELECT 1 FROM domains d
          WHERE d.project_id = m.project_id AND d.tenant_id = m.tenant_id
            AND lower(d.domain) = NEW.email_domain AND d.status = 'verified');
 RETURN NULL;
END; $$;
