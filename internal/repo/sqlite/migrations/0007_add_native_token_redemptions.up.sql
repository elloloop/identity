-- Replay cache for native mobile-SDK ID tokens (Google idToken / Apple
-- identityToken), mirroring the postgres driver's 0022 migration. Native ID
-- tokens are bearer JWTs valid until their `exp`, so a captured token could
-- be redeemed more than once. NativeOAuthLogin records each token's replay
-- key here before issuing a session; the (project_id, replay_key) unique
-- index makes the first redemption win and any later presentation of the
-- SAME token a unique violation -> ErrNativeTokenReplayed.
--
-- replay_key is the token's `jti` when present, else a stable digest of
-- (provider|iss|sub|iat|aud|nonce); no token material or user id is stored.
-- The row is retained only until expires_at_ms so the GC sweeper can reap it.
CREATE TABLE native_token_redemptions (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    replay_key      TEXT NOT NULL,
    expires_at_ms   INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL
);
CREATE UNIQUE INDEX native_token_redemptions_project_key_uidx
    ON native_token_redemptions (project_id, replay_key);
CREATE INDEX native_token_redemptions_project_expires_idx
    ON native_token_redemptions (project_id, expires_at_ms);
