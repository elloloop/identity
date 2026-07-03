-- Optimistic-concurrency token for the per-project config_json blob (#313).
-- Every config_json write is a read-modify-write (admin OAuth authoring,
-- UpsertProjectConfig, and the branding/passkey/cors/login mutators layered on
-- top). A monotonic version lets those writes compare-and-swap on the value they
-- read, so two concurrent admin writes can no longer silently clobber each other
-- (last-writer-wins, a provider vanishing). A dedicated counter — not
-- updated_at_ms — is the token: updated_at_ms has millisecond granularity, so
-- two writes landing in the same millisecond would share a value and defeat the
-- CAS; config_version strictly increases by one per write regardless of clock.
ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS config_version BIGINT NOT NULL DEFAULT 0;
