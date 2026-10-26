-- 0047_end_domain_memberships_off_domain.down.sql
--
-- Drops the trigger that ends a domain membership when the email leaves the
-- domain. The memberships it ended stay ended: the older code reads an
-- inactive membership as no membership, as this code does. lock_timeout
-- bounds the wait for the lock on users, as the up migration does.
SET LOCAL lock_timeout = '10s';

DROP TRIGGER IF EXISTS tenant_domain_membership_email ON users;
DROP FUNCTION IF EXISTS end_domain_memberships_off_domain();
