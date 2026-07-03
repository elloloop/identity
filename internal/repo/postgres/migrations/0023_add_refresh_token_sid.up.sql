-- refresh_tokens gains the access-session link for GATEWAY_REVOCATION_MODE=session.
-- sid carries the same value as the access token's `sid` claim so a path that
-- invalidates the refresh token (a per-tenant session-timeout breach) can also
-- revoke the matching access session, scoped to that one session rather than all
-- of the user's. Empty in mode=ttl and for rows written before this column
-- existed, where there is no session to revoke.
ALTER TABLE refresh_tokens
    ADD COLUMN sid TEXT NOT NULL DEFAULT '';
