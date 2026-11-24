SET LOCAL lock_timeout = '10s';

ALTER TABLE tenant_invitations DROP COLUMN token_only_in_email;
