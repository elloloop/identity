-- 0018_add_passkey_backup_flags.down.sql
ALTER TABLE passkeys
    DROP COLUMN backup_eligible,
    DROP COLUMN backup_state;
