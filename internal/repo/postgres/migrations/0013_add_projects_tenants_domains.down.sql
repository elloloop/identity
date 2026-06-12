-- 0013_add_projects_tenants_domains.down.sql
-- Drop in reverse dependency order so FK children go before their parents.
DROP TABLE IF EXISTS tenant_invitations;
DROP TABLE IF EXISTS tenant_memberships;
DROP TABLE IF EXISTS login_policies;
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS tenants;
DROP TABLE IF EXISTS platform_admins;
DROP TABLE IF EXISTS project_auth_domains;
DROP TABLE IF EXISTS project_credentials;
DROP TABLE IF EXISTS projects;
