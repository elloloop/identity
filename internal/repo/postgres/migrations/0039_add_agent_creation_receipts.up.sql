-- Receipts are durable tombstones, not grants. They intentionally have no
-- user FK: erasing or transferring a subject must never recreate it on retry.
SET LOCAL lock_timeout = '10s';
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

ALTER TABLE agent_creation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_creation_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_creation_receipts_project_isolation ON agent_creation_receipts
 USING(project_id=current_setting('app.current_project_id',true));

CREATE FUNCTION invalidate_agent_creation_receipts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  UPDATE agent_creation_receipts SET invalidated=true WHERE project_id=OLD.project_id AND (agent_id=OLD.id OR owner_id=OLD.id OR caller_id=OLD.id);
  RETURN OLD;
 END IF;
 IF OLD.owner_user_id <> NEW.owner_user_id OR OLD.kind <> NEW.kind OR
 (lower(NEW.status) NOT IN ('','active') AND OLD.status <> NEW.status) OR
 (NOT OLD.is_anonymous AND NEW.is_anonymous) OR
 (OLD.merged_into_user_id <> NEW.merged_into_user_id AND NEW.merged_into_user_id <> '') OR
 (lower(OLD.role) = 'admin' AND lower(NEW.role) <> 'admin') THEN
  UPDATE agent_creation_receipts SET invalidated=true WHERE project_id=OLD.project_id AND (agent_id=OLD.id OR owner_id=OLD.id OR caller_id=OLD.id);
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER users_invalidate_agent_creation_receipts
 AFTER UPDATE OF owner_user_id,kind,status,is_anonymous,merged_into_user_id,role OR DELETE ON users
 FOR EACH ROW EXECUTE FUNCTION invalidate_agent_creation_receipts();
