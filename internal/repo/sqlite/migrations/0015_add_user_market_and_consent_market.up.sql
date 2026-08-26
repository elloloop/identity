-- Per-jurisdiction age thresholds (#462): the jurisdiction/market code an
-- account belongs to (empty = none on file) so its age band derives from that
-- market's configured thresholds, and the market snapshot on each consent
-- record saying which jurisdiction's thresholds the grant proves consent
-- against. Mirrors postgres migration 0030.
ALTER TABLE users
    ADD COLUMN market TEXT NOT NULL DEFAULT '';
ALTER TABLE parental_consents
    ADD COLUMN market TEXT NOT NULL DEFAULT '';
