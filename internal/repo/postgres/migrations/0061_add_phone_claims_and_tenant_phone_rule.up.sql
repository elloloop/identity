-- 0061_add_phone_claims_and_tenant_phone_rule.up.sql
--
-- phone_number_claims is which account holds a verified phone number in a
-- project that keeps numbers unique (phone.unique). Its primary key is the
-- rule: one account per (project, number). It is a table of its own, not a
-- unique index on users.phone_number, because existing deployments may hold
-- one verified number on several accounts and an index would refuse to
-- build. The table starts empty: a number verified before a project turned
-- the rule on is claimed when it is next verified.
--
-- login_policies gains the tenant's phone rule: require_verified_phone
-- refuses a tenant selection until the account has a verified phone, and
-- phone_calling_codes, when set, is the comma-separated calling codes that
-- phone must start with. Both default to no rule, and adding columns with
-- constant defaults rewrites nothing.
SET LOCAL lock_timeout = '10s';

CREATE TABLE phone_number_claims (
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    phone_number  TEXT NOT NULL CHECK (phone_number <> ''),
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    claimed_at_ms BIGINT NOT NULL,
    PRIMARY KEY (project_id, phone_number)
);
CREATE INDEX phone_number_claims_project_user_idx
    ON phone_number_claims (project_id, user_id);
ALTER TABLE phone_number_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE phone_number_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY phone_number_claims_project_isolation ON phone_number_claims
    USING (project_id = current_setting('app.current_project_id', true));

ALTER TABLE login_policies
    ADD COLUMN require_verified_phone BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN phone_calling_codes    TEXT    NOT NULL DEFAULT '';
