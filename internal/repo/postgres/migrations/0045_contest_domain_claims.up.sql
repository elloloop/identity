-- 0045_contest_domain_claims.up.sql
--
-- A domain registration becomes a claim, not a reservation. Until now one
-- (project, domain) row could exist at all, so whoever registered a domain
-- first held it while it was still pending: the real owner could not
-- register it, and the tenant auto-former enrolled the domain's later
-- signups into the first registrant's tenant. Now any tenant may register a
-- domain, at most once per tenant, and only proving it — verification —
-- makes it the tenant's: the verified row is unique per (project, domain).
-- The plain index keeps the by-name lookups the old unique index served.
--
-- The DNS challenge now names the tenant as well as the project and domain,
-- so the record an owner publishes verifies the owner's claim and nobody
-- else's. A dns_txt registration that exists before this migration was
-- handed the older project-wide value; legacy_txt_challenge keeps that value
-- valid for it, and for it alone. That is safe because the old unique index
-- admitted one registration per domain, so each such value went to the one
-- tenant holding the domain when it was issued.
--
-- The constant default makes ADD COLUMN a catalog-only change. The ALTER
-- takes an ACCESS EXCLUSIVE lock that the transaction holds to commit, so
-- reads and writes on domains wait for the rest of the file, including the
-- index builds. lock_timeout bounds the wait to acquire the lock, as in
-- 0034-0044: on timeout the file rolls back
-- and version 45 is left dirty — confirm domains.legacy_txt_challenge is
-- absent, then `identity migrate force 44` and `identity migrate` again.
SET LOCAL lock_timeout = '10s';

ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS legacy_txt_challenge BOOLEAN NOT NULL DEFAULT false;

UPDATE domains SET legacy_txt_challenge = true WHERE verification_method = 'dns_txt';

DROP INDEX IF EXISTS domains_project_domain_uidx;

CREATE UNIQUE INDEX IF NOT EXISTS domains_project_verified_domain_uidx
    ON domains (project_id, lower(domain))
    WHERE status = 'verified';

CREATE UNIQUE INDEX IF NOT EXISTS domains_project_tenant_domain_uidx
    ON domains (project_id, tenant_id, lower(domain));

CREATE INDEX IF NOT EXISTS domains_project_domain_idx
    ON domains (project_id, lower(domain));
