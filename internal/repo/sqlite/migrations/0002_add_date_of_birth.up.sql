-- 0256_add_date_of_birth.up.sql
--
-- COPPA age-gating foundation (sqlite mirror of the postgres migration):
-- store each user's date of birth as epoch milliseconds (0 = unknown) so
-- the service can derive minor status / age band at signup. The derived
-- is_minor / age_band are computed, not stored.
ALTER TABLE users
    ADD COLUMN date_of_birth_ms INTEGER NOT NULL DEFAULT 0;
