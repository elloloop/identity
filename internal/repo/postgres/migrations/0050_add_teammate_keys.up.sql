-- 0050_add_teammate_keys.up.sql
--
-- Teammate keys: one public key per claim, registered by a service holding a
-- teammate_key_manager credential, and the single-use challenges a
-- workstation signs with it. The credential kind is a new value of the
-- existing kind column, so only its CHECK widens; replacing it holds ACCESS
-- EXCLUSIVE on project_credentials while it validates that small table. The
-- two tables are new.
SET LOCAL lock_timeout = '10s';

ALTER TABLE project_credentials DROP CONSTRAINT project_credentials_kind_check;
ALTER TABLE project_credentials ADD CONSTRAINT project_credentials_kind_check
    CHECK (kind IN ('publishable','secret','mtls','directory_reader','teammate_key_manager'));

CREATE TABLE teammate_keys (
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 id TEXT COLLATE "C" NOT NULL,
 claim_id TEXT COLLATE "C" NOT NULL,
 teammate_id TEXT NOT NULL,
 company_id TEXT NOT NULL,
 workstation_id TEXT NOT NULL,
 public_key BYTEA NOT NULL,
 algorithm TEXT NOT NULL CHECK (algorithm IN ('ed25519','ecdsa_p256')),
 created_at_ms BIGINT NOT NULL CHECK (created_at_ms > 0),
 revoked_at_ms BIGINT NOT NULL DEFAULT 0,
 revocation_reason TEXT NOT NULL DEFAULT '' CHECK ((revoked_at_ms = 0) = (revocation_reason = '')),
 PRIMARY KEY(project_id,id),
 UNIQUE(project_id,claim_id),
 UNIQUE(project_id,public_key)
);
CREATE INDEX teammate_keys_revoked_idx ON teammate_keys(project_id,revoked_at_ms,id) WHERE revoked_at_ms <> 0;
ALTER TABLE teammate_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE teammate_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY teammate_keys_project_isolation ON teammate_keys USING (project_id=current_setting('app.current_project_id',true));

CREATE TABLE teammate_key_challenges (
 project_id TEXT NOT NULL,
 id TEXT NOT NULL,
 key_id TEXT COLLATE "C" NOT NULL,
 message TEXT NOT NULL,
 created_at_ms BIGINT NOT NULL,
 expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
 PRIMARY KEY(project_id,id),
 FOREIGN KEY(project_id,key_id) REFERENCES teammate_keys(project_id,id) ON DELETE CASCADE
);
CREATE INDEX teammate_key_challenges_key_idx ON teammate_key_challenges(project_id,key_id,expires_at_ms);
CREATE INDEX teammate_key_challenges_sweep_idx ON teammate_key_challenges(project_id,expires_at_ms,id);
ALTER TABLE teammate_key_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE teammate_key_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY teammate_key_challenges_project_isolation ON teammate_key_challenges USING (project_id=current_setting('app.current_project_id',true));
