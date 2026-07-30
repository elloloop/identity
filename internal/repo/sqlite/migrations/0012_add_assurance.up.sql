-- 0012_add_assurance.up.sql
-- Client-assurance storage: hardware-attested device keys (App Attest)
-- and the one-shot challenges attestation evidence is bound to.
-- Mirrors postgres 0027_add_assurance.

CREATE TABLE attested_devices (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL,
    platform        TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    public_key_spki TEXT NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    environment     TEXT NOT NULL DEFAULT '',
    created_at_ms   INTEGER NOT NULL,
    last_used_at_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX attested_devices_key_uidx
    ON attested_devices (project_id, key_id);

CREATE TABLE assurance_challenges (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL,
    challenge     TEXT NOT NULL,
    platform      TEXT NOT NULL DEFAULT '',
    expires_at_ms INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX assurance_challenges_expiry_idx
    ON assurance_challenges (project_id, expires_at_ms);
