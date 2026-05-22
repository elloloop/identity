-- 0010_add_passwordless_email_login.down.sql

DROP INDEX IF EXISTS magic_link_tokens_tenant_expires_idx;
DROP INDEX IF EXISTS magic_link_tokens_tenant_token_uidx;
DROP TABLE IF EXISTS magic_link_tokens;

DROP INDEX IF EXISTS email_login_codes_tenant_expires_idx;
DROP INDEX IF EXISTS email_login_codes_tenant_email_uidx;
DROP TABLE IF EXISTS email_login_codes;
