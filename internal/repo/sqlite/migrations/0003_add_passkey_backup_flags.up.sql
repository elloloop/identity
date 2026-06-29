-- 0003_add_passkey_backup_flags.up.sql
--
-- sqlite mirror of the postgres migration: persist the WebAuthn Backup
-- Eligible / Backup State flags captured at passkey registration so they can be
-- replayed at login. Without them go-webauthn rejects assertions from backed-up
-- (synced) passkeys, which is virtually all real platform authenticators.
ALTER TABLE passkeys
    ADD COLUMN backup_eligible INTEGER NOT NULL DEFAULT 0;
ALTER TABLE passkeys
    ADD COLUMN backup_state INTEGER NOT NULL DEFAULT 0;
