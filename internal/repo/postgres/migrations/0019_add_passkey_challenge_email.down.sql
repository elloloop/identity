-- 0019_add_passkey_challenge_email.down.sql
ALTER TABLE passkey_challenges
    DROP COLUMN email;
