-- 0030_add_user_market_and_consent_market.down.sql

ALTER TABLE parental_consents
    DROP COLUMN IF EXISTS market;
ALTER TABLE users
    DROP COLUMN IF EXISTS market;
