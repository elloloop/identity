-- 0256_add_date_of_birth.up.sql
--
-- COPPA age-gating foundation: record each user's date of birth so the
-- service layer can derive an age band (ADULT/TEEN/CHILD) and minor status
-- at signup. The value is stored as epoch milliseconds; 0 means "unknown"
-- (no DOB collected), which the age-gate treats as ADULT when the gate is
-- off. The derived is_minor / age_band are NOT persisted — they are
-- computed from this column plus the per-deployment age threshold so the
-- threshold can change without a backfill.
ALTER TABLE users
    ADD COLUMN date_of_birth_ms BIGINT NOT NULL DEFAULT 0;
