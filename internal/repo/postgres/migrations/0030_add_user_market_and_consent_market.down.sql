-- 0030_add_user_market_and_consent_market.down.sql

ALTER TABLE parental_consents
    DROP COLUMN market;
ALTER TABLE users
    DROP COLUMN market;
