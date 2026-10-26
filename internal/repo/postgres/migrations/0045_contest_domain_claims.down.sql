-- 0045_contest_domain_claims.down.sql
--
-- Restores one row per (project, domain). Where tenants contest a domain,
-- the verified row is kept, else the oldest registration; every other claim
-- is deleted, so a tenant that lost the contest must register the domain
-- again after an upgrade. Dropping legacy_txt_challenge is harmless: the
-- older code issues and checks only the project-wide challenge. The deletes
-- fire 0041's domain trigger, which withdraws the project's delegated agent
-- grants exactly as any other domain deletion does. lock_timeout bounds the
-- wait for the locks, as the up migration does.
SET LOCAL lock_timeout = '10s';

DELETE FROM domains d
USING (
    SELECT id, row_number() OVER (
        PARTITION BY project_id, lower(domain)
        ORDER BY (status = 'verified') DESC, created_at_ms, id
    ) AS rank
    FROM domains
) ranked
WHERE d.id = ranked.id AND ranked.rank > 1;

DROP INDEX IF EXISTS domains_project_domain_idx;
DROP INDEX IF EXISTS domains_project_tenant_domain_uidx;
DROP INDEX IF EXISTS domains_project_verified_domain_uidx;

CREATE UNIQUE INDEX IF NOT EXISTS domains_project_domain_uidx
    ON domains (project_id, lower(domain));

ALTER TABLE domains
    DROP COLUMN IF EXISTS legacy_txt_challenge;
