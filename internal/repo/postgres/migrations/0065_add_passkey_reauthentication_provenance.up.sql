SET LOCAL lock_timeout = '10s';
ALTER TABLE passkeys ADD COLUMN reauthentication_eligible BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE refresh_tokens ADD COLUMN credential_enrollment_eligible BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE refresh_tokens ADD COLUMN credential_enrollment_passkey_id TEXT NOT NULL DEFAULT '';
