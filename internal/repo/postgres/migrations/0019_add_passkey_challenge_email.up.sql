-- 0019_add_passkey_challenge_email.up.sql
--
-- Passkey-first signup (unauthenticated account creation via a passkey) mints
-- the new user id during BeginPasskeySignup and binds it as the WebAuthn user
-- handle. The challenge already carries that handle in user_id; this column
-- additionally binds the email the account will be created under, so the email
-- is fixed at the ceremony's start (and shown to the user as the credential's
-- account name) rather than trusted from the CompletePasskeySignup request.
-- Registration / authentication challenges leave it at the empty-string default.
ALTER TABLE passkey_challenges
    ADD COLUMN email TEXT NOT NULL DEFAULT '';
