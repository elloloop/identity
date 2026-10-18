CREATE TABLE agent_machines (
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 id TEXT NOT NULL,
 owner_id TEXT NOT NULL,
 client_id TEXT NOT NULL,
 data_json TEXT NOT NULL,
 registration_json TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK (revision > 0),
 revoked_at_ms INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(project_id,id),
 FOREIGN KEY(project_id,client_id) REFERENCES oauth_clients(project_id,id) ON DELETE CASCADE
);
CREATE INDEX agent_machines_owner_idx ON agent_machines(project_id,owner_id,id);
CREATE INDEX agent_machines_client_idx ON agent_machines(project_id,client_id);
ALTER TABLE agent_authorizations ADD COLUMN machine_id TEXT;
CREATE UNIQUE INDEX agent_authorizations_machine_agent_idx ON agent_authorizations(project_id,machine_id,agent_id) WHERE machine_id IS NOT NULL;
CREATE TRIGGER agent_machine_revoke AFTER UPDATE OF revoked_at_ms ON agent_machines WHEN OLD.revoked_at_ms=0 AND NEW.revoked_at_ms<>0 BEGIN UPDATE agent_authorizations SET revoked_at_ms=NEW.revoked_at_ms,revision=revision+1 WHERE project_id=NEW.project_id AND machine_id=NEW.id AND revoked_at_ms=0; END;
DROP TRIGGER agent_oauth_user_update;
CREATE TRIGGER agent_oauth_user_update AFTER UPDATE OF password_hash,password_change_required,owner_user_id,kind,status,is_anonymous,merged_into_user_id,email,email_verified,idv_verified,date_of_birth_ms,market,role ON users WHEN OLD.password_hash IS NOT NEW.password_hash OR OLD.password_change_required IS NOT NEW.password_change_required OR OLD.owner_user_id IS NOT NEW.owner_user_id OR OLD.kind IS NOT NEW.kind OR OLD.status IS NOT NEW.status OR OLD.is_anonymous IS NOT NEW.is_anonymous OR OLD.merged_into_user_id IS NOT NEW.merged_into_user_id OR OLD.email IS NOT NEW.email OR OLD.email_verified IS NOT NEW.email_verified OR OLD.idv_verified IS NOT NEW.idv_verified OR OLD.date_of_birth_ms IS NOT NEW.date_of_birth_ms OR OLD.market IS NOT NEW.market OR OLD.role IS NOT NEW.role BEGIN UPDATE agent_machines SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND owner_id=OLD.id AND revoked_at_ms=0; UPDATE agent_authorizations SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND (owner_id=OLD.id OR agent_id=OLD.id) AND revoked_at_ms=0; END;
DROP TRIGGER agent_oauth_user_delete;
CREATE TRIGGER agent_oauth_user_delete AFTER DELETE ON users BEGIN UPDATE agent_machines SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND owner_id=OLD.id AND revoked_at_ms=0; UPDATE agent_authorizations SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND (owner_id=OLD.id OR agent_id=OLD.id) AND revoked_at_ms=0; END;
DROP TRIGGER agent_oauth_session_update;
CREATE TRIGGER agent_oauth_session_update AFTER UPDATE OF revoked_at_ms ON sessions WHEN OLD.revoked_at_ms IS NOT NEW.revoked_at_ms BEGIN UPDATE agent_authorizations SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND machine_id IS NULL AND human_sid=OLD.sid AND revoked_at_ms=0; END;
DROP TRIGGER agent_oauth_session_delete;
CREATE TRIGGER agent_oauth_session_delete AFTER DELETE ON sessions BEGIN UPDATE agent_authorizations SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND machine_id IS NULL AND human_sid=OLD.sid AND revoked_at_ms=0; END;
DROP TRIGGER agent_oauth_refresh_delete;
CREATE TRIGGER agent_oauth_refresh_delete AFTER DELETE ON refresh_tokens BEGIN UPDATE agent_authorizations SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND machine_id IS NULL AND human_sid=OLD.sid AND revoked_at_ms=0; END;
DROP TRIGGER agent_oauth_client_update;
CREATE TRIGGER agent_oauth_client_update AFTER UPDATE OF revision ON oauth_clients WHEN OLD.revision IS NOT NEW.revision BEGIN UPDATE agent_machines SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND client_id=OLD.id AND revoked_at_ms=0; UPDATE agent_authorizations SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND client_id=OLD.id AND revoked_at_ms=0; END;
DROP TRIGGER agent_oauth_guardian_delete;
CREATE TRIGGER agent_oauth_guardian_delete AFTER DELETE ON guardian_edges BEGIN UPDATE agent_machines SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND owner_id=OLD.child_user_id AND revoked_at_ms=0; UPDATE agent_authorizations SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.project_id AND owner_id=OLD.child_user_id AND revoked_at_ms=0; END;
DROP TRIGGER agent_oauth_project_policy;
CREATE TRIGGER agent_oauth_project_policy AFTER UPDATE OF config_json,status ON projects WHEN OLD.config_json IS NOT NEW.config_json OR OLD.status IS NOT NEW.status BEGIN UPDATE agent_machines SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.id AND revoked_at_ms=0; UPDATE agent_authorizations SET revoked_at_ms=MAX(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),revision=revision+1 WHERE project_id=OLD.id AND revoked_at_ms=0; END;
