-- 0018_add_passkey_backup_flags.up.sql
--
-- Persist the WebAuthn backup flags captured at passkey registration. The
-- library rejects an assertion whose Backup Eligible / Backup State flags are
-- inconsistent with the stored credential, and every synced platform passkey
-- (iCloud Keychain, Google Password Manager) sets Backup Eligible — so without
-- these columns, passkey login fails for essentially all real authenticators.
-- Existing rows default to false (pre-existing credentials were non-backed-up
-- from the service's point of view); they re-sync on next use.
ALTER TABLE passkeys
    ADD COLUMN backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN backup_state    BOOLEAN NOT NULL DEFAULT FALSE;
