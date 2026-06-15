-- 0014_drop_organizations.up.sql
--
-- Drop the legacy identity-layer Organization / OrganizationMembership
-- tables added in 0007. The Organization model is superseded by the
-- Project/Tenant/Domain model (migration 0013); nothing reads or writes
-- these tables any more. Drop the membership child first so its FK to
-- organizations is gone before the parent is removed.
DROP TABLE IF EXISTS organization_members;
DROP TABLE IF EXISTS organizations;
