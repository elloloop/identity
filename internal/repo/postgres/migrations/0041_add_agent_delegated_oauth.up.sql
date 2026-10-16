SET LOCAL lock_timeout = '10s';
CREATE TABLE agent_authorizations (
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 id TEXT COLLATE "C" NOT NULL,
 client_id TEXT NOT NULL,
 owner_id TEXT NOT NULL DEFAULT '',
 agent_id TEXT NOT NULL DEFAULT '',
 human_sid TEXT NOT NULL DEFAULT '',
 code_hash TEXT NOT NULL DEFAULT '',
 data_json JSONB NOT NULL,
 revision BIGINT NOT NULL CHECK (revision > 0),
 revoked_at_ms BIGINT NOT NULL DEFAULT 0,
 expires_at_ms BIGINT NOT NULL,
 PRIMARY KEY(project_id,id),
 FOREIGN KEY(project_id,client_id) REFERENCES oauth_clients(project_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX agent_authorizations_code_idx ON agent_authorizations(project_id,code_hash) WHERE code_hash <> '';
CREATE INDEX agent_authorizations_owner_idx ON agent_authorizations(project_id,owner_id,id);
CREATE INDEX agent_authorizations_agent_idx ON agent_authorizations(project_id,agent_id);
CREATE INDEX agent_authorizations_sid_idx ON agent_authorizations(project_id,human_sid);
CREATE INDEX agent_authorizations_client_idx ON agent_authorizations(project_id,client_id);
CREATE INDEX agent_authorizations_expiry_idx ON agent_authorizations(project_id,expires_at_ms);
CREATE TABLE agent_oauth_refresh_tokens (
 project_id TEXT NOT NULL,
 token_hash TEXT NOT NULL,
 authorization_id TEXT NOT NULL,
 expires_at_ms BIGINT NOT NULL,
 consumed_at_ms BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(project_id,token_hash),
 FOREIGN KEY(project_id,authorization_id) REFERENCES agent_authorizations(project_id,id) ON DELETE CASCADE
);
ALTER TABLE agent_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_authorizations FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_authorizations_project_isolation ON agent_authorizations USING (project_id=current_setting('app.current_project_id',true));
ALTER TABLE agent_oauth_refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_oauth_refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_oauth_refresh_project_isolation ON agent_oauth_refresh_tokens USING (project_id=current_setting('app.current_project_id',true));
CREATE FUNCTION revoke_agent_oauth_user_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
 WHERE project_id=OLD.project_id AND (owner_id=OLD.id OR agent_id=OLD.id) AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE TRIGGER agent_oauth_user_update AFTER UPDATE OF password_hash,password_change_required,owner_user_id,kind,status,is_anonymous,merged_into_user_id,email,email_verified,idv_verified,date_of_birth_ms,market,role ON users
 FOR EACH ROW WHEN (OLD.password_hash IS DISTINCT FROM NEW.password_hash OR OLD.password_change_required IS DISTINCT FROM NEW.password_change_required OR OLD.owner_user_id IS DISTINCT FROM NEW.owner_user_id OR OLD.kind IS DISTINCT FROM NEW.kind OR OLD.status IS DISTINCT FROM NEW.status OR OLD.is_anonymous IS DISTINCT FROM NEW.is_anonymous OR OLD.merged_into_user_id IS DISTINCT FROM NEW.merged_into_user_id OR OLD.email IS DISTINCT FROM NEW.email OR OLD.email_verified IS DISTINCT FROM NEW.email_verified OR OLD.idv_verified IS DISTINCT FROM NEW.idv_verified OR OLD.date_of_birth_ms IS DISTINCT FROM NEW.date_of_birth_ms OR OLD.market IS DISTINCT FROM NEW.market OR OLD.role IS DISTINCT FROM NEW.role) EXECUTE FUNCTION revoke_agent_oauth_user_authority();
CREATE TRIGGER agent_oauth_user_delete AFTER DELETE ON users FOR EACH ROW EXECUTE FUNCTION revoke_agent_oauth_user_authority();
CREATE FUNCTION revoke_agent_oauth_session_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
 WHERE project_id=OLD.project_id AND human_sid=OLD.sid AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE TRIGGER agent_oauth_session_update AFTER UPDATE OF revoked_at_ms ON sessions FOR EACH ROW WHEN (OLD.revoked_at_ms IS DISTINCT FROM NEW.revoked_at_ms) EXECUTE FUNCTION revoke_agent_oauth_session_authority();
CREATE TRIGGER agent_oauth_session_delete AFTER DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION revoke_agent_oauth_session_authority();
CREATE TRIGGER agent_oauth_refresh_delete AFTER DELETE ON refresh_tokens FOR EACH ROW EXECUTE FUNCTION revoke_agent_oauth_session_authority();
CREATE FUNCTION revoke_agent_oauth_client_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
 WHERE project_id=OLD.project_id AND client_id=OLD.id AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE TRIGGER agent_oauth_client_update AFTER UPDATE OF revision ON oauth_clients FOR EACH ROW WHEN (OLD.revision IS DISTINCT FROM NEW.revision) EXECUTE FUNCTION revoke_agent_oauth_client_authority();
CREATE FUNCTION revoke_agent_oauth_guardian_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1 WHERE project_id=OLD.project_id AND owner_id=OLD.child_user_id AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE TRIGGER agent_oauth_guardian_delete AFTER DELETE ON guardian_edges FOR EACH ROW EXECUTE FUNCTION revoke_agent_oauth_guardian_authority();
-- Control-plane writes have no data-plane GUC. Scope only the security
-- invalidation statement, then restore the caller's original connection scope.
CREATE FUNCTION invalidate_agent_oauth_project(affected_project TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE prior_project TEXT := current_setting('app.current_project_id',true);
BEGIN
 PERFORM set_config('app.current_project_id',affected_project,true);
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1 WHERE project_id=affected_project AND revoked_at_ms=0;
 PERFORM set_config('app.current_project_id',COALESCE(prior_project,''),true);
END; $$;
CREATE FUNCTION revoke_agent_oauth_project_policy() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 PERFORM invalidate_agent_oauth_project(OLD.id);
 RETURN NULL;
END; $$;
CREATE TRIGGER agent_oauth_project_policy AFTER UPDATE OF config_json,status ON projects FOR EACH ROW WHEN (OLD.config_json IS DISTINCT FROM NEW.config_json OR OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION revoke_agent_oauth_project_policy();
CREATE FUNCTION revoke_agent_oauth_governance_policy() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  PERFORM invalidate_agent_oauth_project(NEW.project_id);
 ELSE
  PERFORM invalidate_agent_oauth_project(OLD.project_id);
 END IF;
 RETURN NULL;
END; $$;
-- Tenant policy changes deliberately require fresh consent across the project;
-- restoring a prior policy cannot resurrect a grant admitted under old rules.
CREATE TRIGGER agent_oauth_login_policy AFTER INSERT OR UPDATE OF allowed_methods,sso_required,sso_connection_json,require_2fa,password_min_length,session_idle_timeout_seconds,session_absolute_timeout_seconds OR DELETE ON login_policies FOR EACH ROW EXECUTE FUNCTION revoke_agent_oauth_governance_policy();
CREATE TRIGGER agent_oauth_tenant_policy AFTER UPDATE OF status,primary_domain ON tenants FOR EACH ROW EXECUTE FUNCTION revoke_agent_oauth_governance_policy();
CREATE TRIGGER agent_oauth_domain_policy AFTER UPDATE OF status,tenant_id,domain OR DELETE ON domains FOR EACH ROW EXECUTE FUNCTION revoke_agent_oauth_governance_policy();
CREATE TRIGGER agent_oauth_verified_domain AFTER INSERT ON domains FOR EACH ROW WHEN (NEW.status='verified') EXECUTE FUNCTION revoke_agent_oauth_governance_policy();
