-- 0046_scope_governance_revocation.down.sql
--
-- Restores 0041's tenant and domain triggers: unguarded, and revoking every
-- agent grant and agent machine in the project. Nothing is revoked by the
-- down migration itself. domain_attempts holds only rate-limit history, so
-- dropping it loses nothing the older code reads. lock_timeout bounds the
-- wait for the locks, as the up migration does.
SET LOCAL lock_timeout = '10s';

CREATE INDEX IF NOT EXISTS domains_project_tenant_idx
    ON domains (project_id, tenant_id);
DROP INDEX IF EXISTS domains_project_email_domain_idx;

CREATE INDEX IF NOT EXISTS tenant_invitations_project_tenant_idx
    ON tenant_invitations (project_id, tenant_id);
DROP INDEX IF EXISTS tenant_invitations_project_email_created_idx;
DROP INDEX IF EXISTS tenant_invitations_project_inviter_created_idx;
DROP INDEX IF EXISTS tenant_invitations_project_tenant_created_idx;

DROP TABLE IF EXISTS domain_attempts;

DROP TRIGGER agent_oauth_verified_domain ON domains;
DROP TRIGGER agent_oauth_domain_delete ON domains;
DROP TRIGGER agent_oauth_domain_policy ON domains;
DROP TRIGGER agent_oauth_tenant_policy ON tenants;

CREATE TRIGGER agent_oauth_tenant_policy AFTER UPDATE OF status,primary_domain ON tenants FOR EACH ROW EXECUTE FUNCTION revoke_agent_oauth_governance_policy();
CREATE TRIGGER agent_oauth_domain_policy AFTER UPDATE OF status,tenant_id,domain OR DELETE ON domains FOR EACH ROW EXECUTE FUNCTION revoke_agent_oauth_governance_policy();
CREATE TRIGGER agent_oauth_verified_domain AFTER INSERT ON domains FOR EACH ROW WHEN (NEW.status='verified') EXECUTE FUNCTION revoke_agent_oauth_governance_policy();

DROP FUNCTION revoke_agent_oauth_domain_governance();
DROP FUNCTION revoke_agent_oauth_tenant_governance();
DROP FUNCTION invalidate_agent_oauth_governed(TEXT, TEXT[], TEXT[]);
DROP FUNCTION agent_oauth_governed_users(TEXT, TEXT[], TEXT[]);
