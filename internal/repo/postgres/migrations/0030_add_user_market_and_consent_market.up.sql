-- 0030_add_user_market_and_consent_market.up.sql
--
-- Per-jurisdiction age thresholds (#462): record the jurisdiction/market code
-- an account belongs to so its age band derives from that market's configured
-- thresholds (config_json `jurisdictions`) rather than the deployment-wide
-- GATEWAY_AGEGATE_* pair. Empty means "no market on file" — the project
-- default, then the env thresholds, apply.
--
-- parental_consents.market snapshots the market the child's classification
-- resolved under at grant time, so the consent artifact says WHICH
-- jurisdiction's thresholds it proves consent against.
--
-- Both are plain columns on already-RLS-pinned tables; no new policy is
-- needed.
ALTER TABLE users
    ADD COLUMN market TEXT NOT NULL DEFAULT '';
ALTER TABLE parental_consents
    ADD COLUMN market TEXT NOT NULL DEFAULT '';
