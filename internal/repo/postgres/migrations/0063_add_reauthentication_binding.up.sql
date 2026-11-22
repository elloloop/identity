SET LOCAL lock_timeout = '10s';
ALTER TABLE passkey_challenges ADD COLUMN action TEXT NOT NULL DEFAULT '';
ALTER TABLE passkey_challenges ADD COLUMN resource_id TEXT NOT NULL DEFAULT '';
