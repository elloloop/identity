SET LOCAL lock_timeout = '10s';
DELETE FROM agent_authorizations WHERE machine_id IS NOT NULL;
CREATE OR REPLACE FUNCTION revoke_agent_oauth_user_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
 WHERE project_id=OLD.project_id AND (owner_id=OLD.id OR agent_id=OLD.id) AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION revoke_agent_oauth_session_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
 WHERE project_id=OLD.project_id AND human_sid=OLD.sid AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION revoke_agent_oauth_client_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1
 WHERE project_id=OLD.project_id AND client_id=OLD.id AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION revoke_agent_oauth_guardian_authority() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1 WHERE project_id=OLD.project_id AND owner_id=OLD.child_user_id AND revoked_at_ms=0;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION invalidate_agent_oauth_project(affected_project TEXT) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE prior_project TEXT := current_setting('app.current_project_id',true);
BEGIN
 PERFORM set_config('app.current_project_id',affected_project,true);
 UPDATE agent_authorizations SET revoked_at_ms=GREATEST(1,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT),revision=revision+1 WHERE project_id=affected_project AND revoked_at_ms=0;
 PERFORM set_config('app.current_project_id',COALESCE(prior_project,''),true);
END; $$;
DROP TRIGGER agent_machine_revoke ON agent_machines;
DROP FUNCTION revoke_agent_machine_children();
DROP INDEX agent_authorizations_machine_agent_idx;
ALTER TABLE agent_authorizations DROP COLUMN machine_id;
DROP TABLE agent_machines;
