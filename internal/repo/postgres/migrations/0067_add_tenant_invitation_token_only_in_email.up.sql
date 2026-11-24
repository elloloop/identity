-- 0067_add_tenant_invitation_token_only_in_email.up.sql
--
-- token_only_in_email records that an invitation's raw token went into its
-- email and nowhere else: the service writes true only where its mailer
-- delivers, the one case CreateTenantInvitation does not hand the token to
-- the inviter. Only such a token proves the invited address, so only it may
-- create the account (SignUpWithTenantInvitation) or learn whether the
-- address has one (GetTenantInvitation). Invitations stored before this
-- migration, and any a server older than it stores, keep the default, false:
-- where their token went is unknown. Adding a column with a constant default
-- rewrites nothing.
SET LOCAL lock_timeout = '10s';

ALTER TABLE tenant_invitations ADD COLUMN token_only_in_email BOOLEAN NOT NULL DEFAULT false;
