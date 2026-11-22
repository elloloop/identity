DELETE FROM passkey_challenges WHERE action <> '';
ALTER TABLE passkey_challenges DROP COLUMN resource_id;
ALTER TABLE passkey_challenges DROP COLUMN action;
