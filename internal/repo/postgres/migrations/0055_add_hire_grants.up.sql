-- 0055_add_hire_grants.up.sql
--
-- A teammate key is now registered with a person's hire grant, and that
-- person owns every token the key is exchanged for. hire_grants is new. Each
-- teammate key gains the grant it consumed and its owner; a key registered
-- before grants existed has neither, so it is revoked here, and the CHECK
-- keeps every working key granted. The revocation runs with row security
-- lifted for the table owner only for this transaction: under FORCE it would
-- see no project's rows. revoked_at_ms becomes when a key stops working,
-- which a revocation with a deadline sets in the future.
SET LOCAL lock_timeout = '10s';

CREATE TABLE hire_grants (
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 id TEXT COLLATE "C" NOT NULL,
 owner_user_id TEXT NOT NULL CHECK (owner_user_id <> ''),
 teammate_id TEXT NOT NULL,
 placement_id TEXT NOT NULL,
 company_id TEXT NOT NULL,
 created_at_ms BIGINT NOT NULL CHECK (created_at_ms > 0),
 expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
 used_at_ms BIGINT NOT NULL DEFAULT 0,
 used_claim_id TEXT COLLATE "C" NOT NULL DEFAULT '' CHECK ((used_at_ms = 0) = (used_claim_id = '')),
 PRIMARY KEY(project_id,id)
);
CREATE INDEX hire_grants_sweep_idx ON hire_grants(project_id,expires_at_ms,id);
ALTER TABLE hire_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE hire_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY hire_grants_project_isolation ON hire_grants USING (project_id=current_setting('app.current_project_id',true));

ALTER TABLE teammate_keys NO FORCE ROW LEVEL SECURITY;
UPDATE teammate_keys SET revoked_at_ms = (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT, revocation_reason = 'removed' WHERE revoked_at_ms = 0;
ALTER TABLE teammate_keys FORCE ROW LEVEL SECURITY;

ALTER TABLE teammate_keys
    ADD COLUMN grant_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN owner_user_id TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT teammate_keys_granted CHECK ((grant_id = '') = (owner_user_id = '') AND (grant_id <> '' OR revoked_at_ms <> 0));
