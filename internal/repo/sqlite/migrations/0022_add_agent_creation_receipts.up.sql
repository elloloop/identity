BEGIN;
-- Durable tombstones survive user erasure and are removed with their project.
CREATE TABLE agent_creation_receipts (
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 caller_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 fingerprint TEXT NOT NULL,
 agent_id TEXT NOT NULL,
 owner_id TEXT NOT NULL,
 invalidated BOOLEAN NOT NULL DEFAULT false,
 PRIMARY KEY(project_id, caller_id, request_id)
);
CREATE INDEX agent_creation_receipts_subject_idx ON agent_creation_receipts(project_id,agent_id);
CREATE INDEX agent_creation_receipts_owner_idx ON agent_creation_receipts(project_id,owner_id);

CREATE TRIGGER users_invalidate_agent_creation_receipts_update
 AFTER UPDATE OF owner_user_id,kind,status,is_anonymous,merged_into_user_id,role ON users
 WHEN OLD.owner_user_id <> NEW.owner_user_id OR OLD.kind <> NEW.kind OR
 (lower(NEW.status) NOT IN ('','active') AND OLD.status <> NEW.status) OR
 (NOT OLD.is_anonymous AND NEW.is_anonymous) OR
 (OLD.merged_into_user_id <> NEW.merged_into_user_id AND NEW.merged_into_user_id <> '') OR
 (lower(OLD.role) = 'admin' AND lower(NEW.role) <> 'admin')
 BEGIN
 UPDATE agent_creation_receipts SET invalidated=true WHERE project_id=OLD.project_id AND (agent_id=OLD.id OR owner_id=OLD.id OR caller_id=OLD.id);
 END;
CREATE TRIGGER users_invalidate_agent_creation_receipts_delete AFTER DELETE ON users
 BEGIN
 UPDATE agent_creation_receipts SET invalidated=true WHERE project_id=OLD.project_id AND (agent_id=OLD.id OR owner_id=OLD.id OR caller_id=OLD.id);
 END;
COMMIT;
