ALTER TABLE refresh_tokens DROP COLUMN credential_enrollment_passkey_id;
ALTER TABLE refresh_tokens DROP COLUMN credential_enrollment_eligible;
ALTER TABLE passkeys DROP COLUMN reauthentication_eligible;
