SET LOCAL lock_timeout = '10s';
CREATE TABLE agent_machines (
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 id TEXT COLLATE "C" NOT NULL,
 owner_id TEXT NOT NULL,
 client_id TEXT NOT NULL,
 data_json JSONB NOT NULL,
 registration_json JSONB NOT NULL,
 revision BIGINT NOT NULL CHECK (revision > 0),
 revoked_at_ms BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(project_id,id),
 FOREIGN KEY(project_id,client_id) REFERENCES oauth_clients(project_id,id) ON DELETE CASCADE
);
CREATE INDEX agent_machines_owner_idx ON agent_machines(project_id,owner_id,id);
CREATE INDEX agent_machines_client_idx ON agent_machines(project_id,client_id);
ALTER TABLE agent_authorizations ADD COLUMN machine_id TEXT;
CREATE UNIQUE INDEX agent_authorizations_machine_agent_idx ON agent_authorizations(project_id,machine_id,agent_id) WHERE machine_id IS NOT NULL;
ALTER TABLE agent_machines ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_machines FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_machines_project_isolation ON agent_machines USING (project_id=current_setting('app.current_project_id',true));
CREATE FUNCTION revoke_agent_machine_children() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_authorizations SET revoked_at_ms=NEW.revoked_at_ms,revision=revision+1 WHERE project_id=NEW.project_id AND machine_id=NEW.id AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE TRIGGER agent_machine_revoke AFTER UPDATE OF revoked_at_ms ON agent_machines FOR EACH ROW WHEN (OLD.revoked_at_ms=0 AND NEW.revoked_at_ms<>0) EXECUTE FUNCTION revoke_agent_machine_children();
CREATE OR REPLACE FUNCTION revoke_agent_oauth_user_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_machines SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1 WHERE project_id=OLD.project_id AND owner_id=OLD.id AND revoked_at_ms=0;
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
 WHERE project_id=OLD.project_id AND (owner_id=OLD.id OR agent_id=OLD.id) AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION revoke_agent_oauth_session_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
 WHERE project_id=OLD.project_id AND machine_id IS NULL AND human_sid=OLD.sid AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION revoke_agent_oauth_client_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_machines SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1 WHERE project_id=OLD.project_id AND client_id=OLD.id AND revoked_at_ms=0;
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
 WHERE project_id=OLD.project_id AND client_id=OLD.id AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION revoke_agent_oauth_guardian_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_machines SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1 WHERE project_id=OLD.project_id AND owner_id=OLD.child_user_id AND revoked_at_ms=0;
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1 WHERE project_id=OLD.project_id AND owner_id=OLD.child_user_id AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION invalidate_agent_oauth_project(affected_project TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE prior_project TEXT := current_setting('app.current_project_id',true);
BEGIN
 PERFORM set_config('app.current_project_id',affected_project,true);
 UPDATE agent_machines SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1 WHERE project_id=affected_project AND revoked_at_ms=0;
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1 WHERE project_id=affected_project AND revoked_at_ms=0;
 PERFORM set_config('app.current_project_id',COALESCE(prior_project,''),true);
END; $$;

CREATE TABLE agent_machine_challenges (
 project_id TEXT NOT NULL,
 id TEXT NOT NULL,
 machine_id TEXT NOT NULL,
 data_json JSONB NOT NULL,
 created_at_ms BIGINT NOT NULL,
 expires_at_ms BIGINT NOT NULL,
 PRIMARY KEY(project_id,id),
 FOREIGN KEY(project_id,machine_id) REFERENCES agent_machines(project_id,id) ON DELETE CASCADE
);
CREATE INDEX agent_machine_challenges_expiry_idx ON agent_machine_challenges(project_id,machine_id,expires_at_ms);
ALTER TABLE agent_machine_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_machine_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_machine_challenges_project_isolation ON agent_machine_challenges USING(project_id=current_setting('app.current_project_id',true));

CREATE UNIQUE INDEX agent_authorizations_machine_key_idx ON agent_authorizations(project_id,machine_id,(data_json->>'MachinePublicKey')) WHERE machine_id IS NOT NULL;
CREATE INDEX agent_machine_challenges_sweep_idx ON agent_machine_challenges(project_id,expires_at_ms,id);
