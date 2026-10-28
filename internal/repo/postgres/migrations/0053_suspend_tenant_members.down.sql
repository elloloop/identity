-- 0053_suspend_tenant_members.down.sql
--
-- A suspended membership becomes 'inactive', the nearest older meaning (a
-- membership that no longer lets its holder act), so the original status
-- CHECK holds again. The person is then no longer a member: an invitation
-- lets them back in, and so does joining by domain where the domain lets
-- people join. The trigger again ends every domain membership whose email
-- leaves the domain, as 0047 wrote it. lock_timeout bounds the wait for the
-- locks, as the up migration does.
SET LOCAL lock_timeout = '10s';

UPDATE tenant_memberships SET status = 'inactive' WHERE status = 'suspended';

ALTER TABLE tenant_memberships DROP CONSTRAINT IF EXISTS tenant_memberships_status_check;
ALTER TABLE tenant_memberships
    ADD CONSTRAINT tenant_memberships_status_check
    CHECK (status IN ('active', 'pending', 'inactive'));

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
