-- refresh_tokens gains the sign-in's time. auth_time_ms is the moment the
-- person authenticated the session (the access token's auth_time claim), set by
-- a sign-in and copied unchanged across rotations, so a token refreshed from a
-- sign-in still says when the person signed in. 0 means no sign-in opened the
-- session (a QR hand-off, an anonymous session) or a legacy row from before
-- this column; such a session's tokens carry no auth_time.
ALTER TABLE refresh_tokens ADD COLUMN auth_time_ms INTEGER NOT NULL DEFAULT 0;
