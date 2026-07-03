-- refresh_tokens gains the access-session link for GATEWAY_REVOCATION_MODE=session.
-- sid carries the same value as the access token's `sid` claim so a session-timeout
-- breach that deletes the refresh token can also revoke the matching access session,
-- scoped to that one session. Empty in mode=ttl and for legacy rows.
ALTER TABLE refresh_tokens ADD COLUMN sid TEXT NOT NULL DEFAULT '';
