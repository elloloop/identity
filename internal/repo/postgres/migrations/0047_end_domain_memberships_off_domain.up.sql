-- 0047_end_domain_memberships_off_domain.up.sql
--
-- A membership that came from an email's domain (source 'domain') ends when
-- that email leaves the domain. Before this, it outlived the address that
-- earned it: an account could sign up unverified on a company's domain,
-- gain the domain membership, and then confirm an email change to an address
-- it does control, which verifies the account and kept the membership. The
-- active-tenant reads now also require the email to be on a domain the
-- tenant has verified; this ends the membership at the change itself, in the
-- same transaction, whichever path changes the email: a confirmed email
-- change, SCIM, the admin API or an account merge.
--
-- The trigger fires only when users.email_domain (0046) changes, so a change
-- within the domain, a change of case included, fires nothing. It ends each
-- of the account's domain memberships whose tenant has not verified the new
-- domain, so a move between two domains one tenant has verified keeps that
-- tenant. Memberships from any other source, and the user's other rows, are
-- untouched. An account that comes back to the domain is not joined again
-- by the change: an invitation or an admin's grant makes it a member, and
-- the ended row is what that grant reactivates. tenant_memberships and
-- domains have no row-level security, so
-- the trigger reads and writes them whatever project the session is bound
-- to.
--
-- Locks: CREATE TRIGGER holds a SHARE ROW EXCLUSIVE lock on users, which
-- blocks writes to it, sign-in's included, for as long as the catalog change
-- takes, and reads continue. lock_timeout bounds only the wait to acquire
-- it, as in 0034-0046. On a timeout the file rolls back and version 47 is
-- left dirty: `identity migrate force 46`, then `identity migrate` again.
SET LOCAL lock_timeout = '10s';

CREATE FUNCTION end_domain_memberships_off_domain() RETURNS TRIGGER LANGUAGE plpgsql AS $$
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

CREATE TRIGGER tenant_domain_membership_email AFTER UPDATE OF email ON users FOR EACH ROW
 WHEN (OLD.email_domain IS DISTINCT FROM NEW.email_domain)
 EXECUTE FUNCTION end_domain_memberships_off_domain();
