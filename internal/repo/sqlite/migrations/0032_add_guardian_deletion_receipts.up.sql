CREATE TABLE guardian_deletion_receipts (
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 guardian_user_id TEXT NOT NULL,
 child_user_id TEXT NOT NULL,
 completed_at_ms INTEGER NOT NULL,
 PRIMARY KEY(project_id,guardian_user_id,child_user_id)
);
