-- 0027_add_assurance.up.sql
--
-- Client-assurance storage: hardware-attested device keys (App Attest)
-- and the one-shot challenges attestation evidence is bound to.
--
-- Conventions match 0001_init/0013 (TEXT PKs, BIGINT epoch-ms timestamps,
-- project_id leading every index) plus the conventions 0015/0016 added for
-- every data-plane table and 0022 last applied: project_id carries the
-- FOREIGN KEY to projects(id) ON DELETE CASCADE (a row can only exist under
-- a real control-plane Project, and dropping a project reaps its rows), and
-- both tables enable + force row-level security with a project-isolation
-- policy.

CREATE TABLE attested_devices (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    platform        TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    public_key_spki TEXT NOT NULL,
    sign_count      BIGINT NOT NULL DEFAULT 0,
    environment     TEXT NOT NULL DEFAULT '',
    created_at_ms   BIGINT NOT NULL,
    last_used_at_ms BIGINT NOT NULL
);
-- One hardware key, one record, per project.
CREATE UNIQUE INDEX attested_devices_key_uidx
    ON attested_devices (project_id, key_id);
-- Backing index for the staleness sweep: a device row is permanent until
-- reaped, and a reinstall or key regeneration mints a NEW key id, so
-- without retention the table only ever grows.
CREATE INDEX attested_devices_last_used_idx
    ON attested_devices (project_id, last_used_at_ms);

CREATE TABLE assurance_challenges (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    challenge     TEXT NOT NULL,
    platform      TEXT NOT NULL DEFAULT '',
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
-- Backing index for the expiry sweep.
CREATE INDEX assurance_challenges_expiry_idx
    ON assurance_challenges (project_id, expires_at_ms);

-- Row-level security: pin every row to the request's project, matching the
-- data-plane isolation posture migration 0016 established and 0022 last
-- applied. Both tables hold per-project hardware key material (SPKI) and the
-- replay-protection counter, so the second isolation boundary matters here.
ALTER TABLE attested_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE attested_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY attested_devices_project_isolation ON attested_devices
    USING (project_id = current_setting('app.current_project_id', true));

ALTER TABLE assurance_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE assurance_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY assurance_challenges_project_isolation ON assurance_challenges
    USING (project_id = current_setting('app.current_project_id', true));
