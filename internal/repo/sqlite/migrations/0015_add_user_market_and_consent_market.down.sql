-- Own transaction: this driver runs migrations with NoTxWrap, so the two
-- drops must not be able to half-apply (mirrors the up migration).
BEGIN;
ALTER TABLE parental_consents DROP COLUMN market;
ALTER TABLE users DROP COLUMN market;
COMMIT;
