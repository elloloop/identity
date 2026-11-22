SET LOCAL lock_timeout = '10s';
-- No user FK: the receipt must outlive the erased child and its guardian edge.
CREATE TABLE guardian_deletion_receipts (
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 guardian_user_id TEXT NOT NULL,
 child_user_id TEXT NOT NULL,
 completed_at_ms BIGINT NOT NULL,
 PRIMARY KEY(project_id,guardian_user_id,child_user_id)
);
ALTER TABLE guardian_deletion_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE guardian_deletion_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY guardian_deletion_receipts_project_isolation ON guardian_deletion_receipts
 USING(project_id=current_setting('app.current_project_id',true));
