-- 0046_scope_governance_revocation.up.sql
--
-- Tenant and domain changes withdraw only the delegated agent authority they
-- govern. 0041's tenant and domain triggers fired on every write to those
-- columns and revoked every agent grant and agent machine in the project.
-- Once a signed-in user could own a tenant (0044), that made any tenant
-- owner able to sign the whole project's agents out: a failed VerifyDomain
-- wrote status = 'failed' on a claim nobody had verified, and each such write
-- revoked everything.
--
-- Now a trigger fires only on a change that moves governance:
--   - a domain row that is, or becomes, verified changes status, tenant or
--     name, or is inserted verified or deleted while verified;
--   - a tenant changes status or primary domain.
-- A pending claim turning failed, or a status written again unchanged, fires
-- nothing. And what fires revokes only the grants and machines of the users
-- the change governs: the members of the tenants involved and the accounts
-- whose email is on the domains involved (ADR-0018). Login-policy and
-- project changes are operator actions and still revoke project-wide (0041).
--
-- The accounts on a domain are found through users.email_domain, the
-- address's domain under the ASCII fold of 0034, and its index. It is a
-- stored column rather than an expression index for 0034's reason: under
-- FORCE ROW LEVEL SECURITY (0016) a predicate is an index condition only if
-- every function in it is leakproof, and lower() and substring() are not, so
-- an index on the expression would serve only project_id and the domain
-- would be matched by scanning every account in the project.
--
-- Also here, for the self-service limits and lookups:
--   - domain_attempts records each CreateDomain and VerifyDomain a tenant
--     makes, so the service can cap them per tenant in a window;
--   - tenant_invitations gains the indexes the invitation limits count over,
--     replacing the (project, tenant) one they extend;
--   - domains gains a partial index for the auto-former's fallback to the
--     latent tenant an email domain formed, and drops (project, tenant),
--     which 0045's (project, tenant, lower(domain)) unique index covers;
--   - 0044's widened membership-source check, added NOT VALID, is validated.
--
-- Locks, in the order taken, each held until commit:
--   - adding email_domain rewrites users under an ACCESS EXCLUSIVE lock, for
--     a time proportional to the table's size, and its index is then built in
--     the same transaction: sign-in, refresh and SCIM wait for both;
--   - each other CREATE INDEX holds a SHARE lock on its table, blocking writes
--     to it while reads continue;
--   - VALIDATE CONSTRAINT holds SHARE UPDATE EXCLUSIVE on tenant_memberships,
--     which blocks neither reads nor writes;
--   - DROP INDEX and DROP TRIGGER take ACCESS EXCLUSIVE on tenant_invitations,
--     domains and tenants, blocking reads too, so they come last, after every
--     build.
-- lock_timeout bounds only the wait to ACQUIRE each lock, as in 0034-0045,
-- not the rewrite: size the maintenance window from users. On a timeout, or
-- any failure, the file rolls back and version 46 is left dirty: confirm the
-- table domain_attempts is absent, then `identity migrate force 45` and
-- `identity migrate` again. The IF NOT EXISTS guards let an operator add the
-- column by hand in a window and pre-build its index with CREATE INDEX
-- CONCURRENTLY (docs/UPGRADE.md), and have this file no-op over them.
SET LOCAL lock_timeout = '10s';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_domain TEXT COLLATE "C"
        GENERATED ALWAYS AS (substring(lower(email COLLATE "C") FROM '@([^@]*)$')) STORED;
CREATE INDEX IF NOT EXISTS users_project_email_domain_idx
    ON users (project_id, email_domain)
    WHERE email_domain IS NOT NULL;

-- One row per CreateDomain or VerifyDomain a tenant made. The service counts
-- a tenant's rows in its window and prunes the older ones as it adds one, so
-- a tenant holds at most its cap. Governance plane: no row-level security,
-- like the other governance tables.
CREATE TABLE domain_attempts (
    id               TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    attempted_at_ms  BIGINT NOT NULL
);
CREATE INDEX domain_attempts_project_tenant_idx
    ON domain_attempts (project_id, tenant_id, attempted_at_ms);

-- The invitation limits count a tenant's, an inviter's, and a tenant's to
-- one recipient, invitations created since a window start.
CREATE INDEX IF NOT EXISTS tenant_invitations_project_tenant_created_idx
    ON tenant_invitations (project_id, tenant_id, created_at_ms);
CREATE INDEX IF NOT EXISTS tenant_invitations_project_inviter_created_idx
    ON tenant_invitations (project_id, invited_by, created_at_ms);
CREATE INDEX IF NOT EXISTS tenant_invitations_project_tenant_email_created_idx
    ON tenant_invitations (project_id, tenant_id, lower(email COLLATE "C"), created_at_ms);

-- The auto-former's fallback: the oldest email-method row on a domain.
CREATE INDEX IF NOT EXISTS domains_project_email_domain_idx
    ON domains (project_id, lower(domain), created_at_ms, id)
    WHERE verification_method = 'email';

ALTER TABLE tenant_memberships VALIDATE CONSTRAINT tenant_memberships_source_check;

-- The accounts whose email is on one of these domains. A plain SQL function,
-- so the planner inlines it into the caller and the domain predicate is an
-- index condition on users_project_email_domain_idx. users is under
-- row-level security, so the caller sets app.current_project_id first.
CREATE FUNCTION agent_oauth_domain_users(affected_project TEXT, affected_domains TEXT[])
RETURNS TABLE (user_id TEXT) LANGUAGE sql STABLE AS $$
 SELECT u.id FROM users u
  WHERE u.project_id = affected_project AND u.email_domain = ANY(affected_domains)
$$;

-- Revokes the agent machines and the agent grants of the users a change on
-- these tenants and email domains governs: every member of the tenants,
-- whatever their membership's status, and every account whose email is on
-- one of the domains. The set is read once; the accounts on the domains only
-- when there are domains. Revoking a machine also revokes its grants (0042).
CREATE FUNCTION invalidate_agent_oauth_governed(affected_project TEXT, affected_tenants TEXT[], affected_domains TEXT[])
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
 prior_project TEXT := current_setting('app.current_project_id',true);
 governed TEXT[];
BEGIN
 PERFORM set_config('app.current_project_id',affected_project,true);
 governed := ARRAY(SELECT m.user_id FROM tenant_memberships m
                    WHERE m.project_id=affected_project AND m.tenant_id = ANY(affected_tenants));
 IF cardinality(affected_domains) > 0 THEN
  governed := governed || ARRAY(SELECT d.user_id FROM agent_oauth_domain_users(affected_project,affected_domains) d);
 END IF;
 IF cardinality(governed) > 0 THEN
  UPDATE agent_machines SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
   WHERE project_id=affected_project AND revoked_at_ms=0 AND owner_id = ANY(governed);
  UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
   WHERE project_id=affected_project AND revoked_at_ms=0
     AND (owner_id = ANY(governed) OR agent_id = ANY(governed));
 END IF;
 PERFORM set_config('app.current_project_id',COALESCE(prior_project,''),true);
END; $$;

-- A tenant's status or primary domain changed: its members, and the accounts
-- on the domains it has verified and on its old and new primary domain.
CREATE FUNCTION revoke_agent_oauth_tenant_governance() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 PERFORM invalidate_agent_oauth_governed(
  OLD.project_id,
  ARRAY[OLD.id],
  array_remove(
   ARRAY(SELECT lower(d.domain) FROM domains d
         WHERE d.project_id=OLD.project_id AND d.tenant_id=OLD.id AND d.status='verified')
   || ARRAY[lower(OLD.primary_domain), lower(NEW.primary_domain)],
   ''));
 RETURN NULL;
END; $$;

-- A verified domain row was inserted, changed or deleted: the members of the
-- tenants that held or now hold it, and the accounts on its old and new name.
CREATE FUNCTION revoke_agent_oauth_domain_governance() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  PERFORM invalidate_agent_oauth_governed(NEW.project_id, ARRAY[NEW.tenant_id], ARRAY[lower(NEW.domain)]);
 ELSIF TG_OP='DELETE' THEN
  PERFORM invalidate_agent_oauth_governed(OLD.project_id, ARRAY[OLD.tenant_id], ARRAY[lower(OLD.domain)]);
 ELSE
  PERFORM invalidate_agent_oauth_governed(OLD.project_id, ARRAY[OLD.tenant_id, NEW.tenant_id], ARRAY[lower(OLD.domain), lower(NEW.domain)]);
 END IF;
 RETURN NULL;
END; $$;

DROP TRIGGER agent_oauth_tenant_policy ON tenants;
DROP TRIGGER agent_oauth_domain_policy ON domains;
DROP TRIGGER agent_oauth_verified_domain ON domains;

CREATE TRIGGER agent_oauth_tenant_policy AFTER UPDATE OF status,primary_domain ON tenants FOR EACH ROW
 WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.primary_domain IS DISTINCT FROM NEW.primary_domain)
 EXECUTE FUNCTION revoke_agent_oauth_tenant_governance();
CREATE TRIGGER agent_oauth_domain_policy AFTER UPDATE OF status,tenant_id,domain ON domains FOR EACH ROW
 WHEN ((OLD.status='verified' OR NEW.status='verified')
   AND (OLD.status IS DISTINCT FROM NEW.status
     OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
     OR lower(OLD.domain) IS DISTINCT FROM lower(NEW.domain)))
 EXECUTE FUNCTION revoke_agent_oauth_domain_governance();
CREATE TRIGGER agent_oauth_domain_delete AFTER DELETE ON domains FOR EACH ROW
 WHEN (OLD.status='verified')
 EXECUTE FUNCTION revoke_agent_oauth_domain_governance();
CREATE TRIGGER agent_oauth_verified_domain AFTER INSERT ON domains FOR EACH ROW
 WHEN (NEW.status='verified')
 EXECUTE FUNCTION revoke_agent_oauth_domain_governance();

DROP INDEX IF EXISTS tenant_invitations_project_tenant_idx;
DROP INDEX IF EXISTS domains_project_tenant_idx;
