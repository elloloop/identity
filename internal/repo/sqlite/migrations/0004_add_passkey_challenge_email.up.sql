-- 0004_add_passkey_challenge_email.up.sql
--
-- sqlite mirror of the postgres migration: bind the email a passkey-first
-- signup will create the account under to the challenge, so it is fixed at the
-- ceremony's start rather than trusted from the CompletePasskeySignup request.
-- Registration / authentication challenges leave it at the empty-string default.
ALTER TABLE passkey_challenges
    ADD COLUMN email TEXT NOT NULL DEFAULT '';
