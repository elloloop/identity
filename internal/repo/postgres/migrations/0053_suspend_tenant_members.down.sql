-- 0053_suspend_tenant_members.down.sql
--
-- Version 52 cannot hold a suspension: 'suspended' fails its status CHECK,
-- and every status it has would let the person back on their own, through
-- an invitation they already hold or a join by their email's domain. So
-- this file refuses to run while any membership is suspended, and each one
-- is decided first: the tenant's owners and admins restore it
-- (RestoreTenantMember) or remove it (RemoveTenantMember, whose removal
-- record keeps a domain member from joining again), or an operator removes
-- it in SQL as docs/UPGRADE.md shows. The refusal rolls the file back and
-- records version 52 dirty: run this release's `identity migrate force 53`,
-- decide the suspensions, then migrate down again.
--
-- The table lock comes first, so no suspension lands between the check and
-- the constraint; membership reads wait while the check reads the table. The narrower CHECK is re-added NOT VALID: the check has
-- just read every row under that lock, so the scan a valid one runs would
-- find nothing, and every later write is checked. The trigger again ends
-- every domain membership whose email leaves the domain, as 0047 wrote it.
-- lock_timeout bounds the wait for the locks, as the up migration does.
SET LOCAL lock_timeout = '10s';

LOCK TABLE tenant_memberships IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
 suspended BIGINT;
BEGIN
 SELECT count(*) INTO suspended FROM tenant_memberships WHERE status = 'suspended';
 IF suspended > 0 THEN
  RAISE EXCEPTION 'tenant memberships suspended: %; restore or remove each before migrating below 0053', suspended;
 END IF;
END $$;

ALTER TABLE tenant_memberships DROP CONSTRAINT IF EXISTS tenant_memberships_status_check;
ALTER TABLE tenant_memberships
    ADD CONSTRAINT tenant_memberships_status_check
    CHECK (status IN ('active', 'pending', 'inactive')) NOT VALID;

CREATE OR REPLACE FUNCTION end_domain_memberships_off_domain() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE tenant_memberships m
    SET status = 'inactive',
        updated_at_ms = (EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT
  WHERE m.project_id = NEW.project_id AND m.user_id = NEW.id
    AND m.source = 'domain' AND m.status <> 'inactive'
    AND NOT EXISTS (
         SELECT 1 FROM domains d
          WHERE d.project_id = m.project_id AND d.tenant_id = m.tenant_id
            AND lower(d.domain) = NEW.email_domain AND d.status = 'verified');
 RETURN NULL;
END; $$;
