-- 0029_add_parental_consents.up.sql
--
-- Verifiable Parental Consent records (COPPA / DPDP / UK Children's Code).
-- Each row is the auditable, revocable artifact proving a specific adult
-- (consenting_user_id) granted parental consent for a specific child account
-- (child_user_id), transitioning the child out of pending_parental_consent.
--
-- child_user_id and consenting_user_id are plain TEXT with NO users(id)
-- foreign key: like audit_events, a consent record must survive the deletion
-- of either user it references (the proof of consent is retained on DeleteUser
-- for accountability, to defend a regulatory inquiry raised after an account is
-- closed). project_id carries the FK to projects(id) ON DELETE CASCADE that
-- every data-plane table gained in migration 0015.
--
-- factors is a canonical comma-separated list of the strong verified factors
-- present on the adult's account at the moment of consent (verified_phone /
-- passkey / identity_verification). revoked_at_ms = 0 marks an active consent.

CREATE TABLE parental_consents (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    child_user_id       TEXT NOT NULL,
    consenting_user_id  TEXT NOT NULL,
    policy_version      TEXT NOT NULL DEFAULT '',
    factors             TEXT NOT NULL DEFAULT '',
    stepped_up          BOOLEAN NOT NULL DEFAULT FALSE,
    consent_ip          TEXT NOT NULL DEFAULT '',
    consent_user_agent  TEXT NOT NULL DEFAULT '',
    granted_at_ms       BIGINT NOT NULL,
    revoked_at_ms       BIGINT NOT NULL DEFAULT 0,
    revoked_by_user_id  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX parental_consents_project_child_idx
    ON parental_consents (project_id, child_user_id, granted_at_ms DESC);

-- Row-level security: pin every row to the request's project, matching the
-- data-plane isolation posture migration 0016 established for the other tables.
ALTER TABLE parental_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE parental_consents FORCE ROW LEVEL SECURITY;
CREATE POLICY parental_consents_project_isolation ON parental_consents
    USING (project_id = current_setting('app.current_project_id', true));
