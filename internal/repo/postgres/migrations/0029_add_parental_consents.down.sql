-- 0029_add_parental_consents.down.sql

DROP POLICY IF EXISTS parental_consents_project_isolation ON parental_consents;
DROP INDEX IF EXISTS parental_consents_project_child_idx;
DROP TABLE IF EXISTS parental_consents;
