-- 0031_add_guardian_edges.down.sql

DROP POLICY IF EXISTS guardian_edges_project_isolation ON guardian_edges;
DROP INDEX IF EXISTS guardian_edges_project_child_idx;
DROP TABLE IF EXISTS guardian_edges;
