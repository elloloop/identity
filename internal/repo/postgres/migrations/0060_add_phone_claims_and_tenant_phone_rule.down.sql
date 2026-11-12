-- 0060_add_phone_claims_and_tenant_phone_rule.down.sql
--
-- Drops the phone claims and every tenant's phone rule. Verified numbers stay
-- on their accounts; nothing keeps them unique afterwards, and a tenant that
-- required a verified phone no longer does.
SET LOCAL lock_timeout = '10s';

ALTER TABLE login_policies
    DROP COLUMN phone_calling_codes,
    DROP COLUMN require_verified_phone;
DROP TABLE phone_number_claims;
