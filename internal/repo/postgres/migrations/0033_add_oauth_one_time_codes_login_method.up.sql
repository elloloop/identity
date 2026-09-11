-- 0033_add_oauth_one_time_codes_login_method.up.sql
--
-- Hosted action pages (ADR-0014): the single-use handover code is no longer
-- minted only by the hosted OAuth callback — the hosted magic-link page mints
-- one too, so an app redeems every hosted sign-in the same way. Redeem must
-- enforce the login policy and write the audit event of the flow that minted
-- the code, so each row now records that flow ('oauth' or 'magic_link').
-- Every row that predates the column was minted by OAuth, which the default
-- preserves.
ALTER TABLE oauth_one_time_codes
    ADD COLUMN login_method TEXT NOT NULL DEFAULT 'oauth'
        CHECK (login_method IN ('oauth', 'magic_link'));
