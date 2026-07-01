-- 0022_add_native_token_redemptions.up.sql
--
-- Replay cache for native mobile-SDK ID tokens (Google idToken / Apple
-- identityToken). These are bearer JWTs valid until their `exp` (~1h for
-- Google; the Apple nonce is client-optional), so a captured token could be
-- redeemed more than once. NativeOAuthLogin records each token's replay key
-- here before issuing a session; the (project_id, replay_key) unique index
-- makes the first redemption win and any later presentation of the SAME
-- token a unique violation → ErrNativeTokenReplayed. This is the
-- multi-replica serialization point (see #299 item 2).
--
-- replay_key is the token's `jti` when present, else a stable digest of
-- (provider|iss|sub|iat|aud|nonce); no token material or user id is stored.
-- The row is retained only until expires_at_ms (= the token's `exp`, capped)
-- so the GC sweeper can reap it once the token can no longer be presented.
--
-- project_id carries the FOREIGN KEY to projects(id) ON DELETE CASCADE that
-- every data-plane / ephemeral-auth table gained in migration 0015 (and that
-- the sqlite driver's 0007 mirror also has): a redemption row can only exist
-- under a real control-plane Project, and dropping a project reaps its rows.
--
-- Indexes:
--   * (project_id, replay_key) unique — the insert-or-reject CAS target.
--   * (project_id, expires_at_ms) — for the GC sweeper batch delete.

CREATE TABLE native_token_redemptions (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    replay_key      TEXT NOT NULL,
    expires_at_ms   BIGINT NOT NULL,
    created_at_ms   BIGINT NOT NULL
);
CREATE UNIQUE INDEX native_token_redemptions_project_key_uidx
    ON native_token_redemptions (project_id, replay_key);
CREATE INDEX native_token_redemptions_project_expires_idx
    ON native_token_redemptions (project_id, expires_at_ms);

-- Row-level security: pin every row to the request's project, matching the
-- data-plane isolation posture migration 0016 established for the other
-- ephemeral-auth tables.
ALTER TABLE native_token_redemptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE native_token_redemptions FORCE ROW LEVEL SECURITY;
CREATE POLICY native_token_redemptions_project_isolation ON native_token_redemptions
    USING (project_id = current_setting('app.current_project_id', true));
