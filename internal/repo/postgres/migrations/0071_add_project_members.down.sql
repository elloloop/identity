-- 0071_add_project_members.down.sql
--
-- Drops the record of which console accounts manage which projects. The
-- projects themselves stay, with their config and credentials; with the
-- memberships gone nobody reaches them through the console, and the operator
-- manages them with the admin secret as before.
SET LOCAL lock_timeout = '10s';

DROP TABLE IF EXISTS project_members;
