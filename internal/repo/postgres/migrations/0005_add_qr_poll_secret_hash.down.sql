ALTER TABLE qr_login_sessions
    DROP COLUMN IF EXISTS poll_secret_hash;
