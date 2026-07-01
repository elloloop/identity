-- 0022_add_native_token_redemptions.down.sql

DROP POLICY IF EXISTS native_token_redemptions_project_isolation ON native_token_redemptions;
DROP INDEX IF EXISTS native_token_redemptions_project_expires_idx;
DROP INDEX IF EXISTS native_token_redemptions_project_key_uidx;
DROP TABLE IF EXISTS native_token_redemptions;
