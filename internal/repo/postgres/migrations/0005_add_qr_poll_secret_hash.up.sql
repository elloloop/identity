ALTER TABLE qr_login_sessions
    ADD COLUMN IF NOT EXISTS poll_secret_hash TEXT NOT NULL DEFAULT '';
