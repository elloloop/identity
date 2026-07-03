package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

// The control-plane admin RPCs are PLATFORM-operator operations, authenticated
// by the shared admin secret in the AdminAPISecretHeader (NOT a user JWT). The
// handler extracts that header and hands it to the service, which compares it
// in constant time and — when no secret is configured — returns Unimplemented.
//
// h.controlAdmin is nil on memory (no control plane), which also yields
// Unimplemented, so the surface is doubly off by default: no control plane OR
// no configured secret both disable it.

// adminSecret reads the operator's presented admin secret from the request.
func adminSecret(headers headerReader) string {
	return headers.Get(middleware.AdminAPISecretHeader)
}

// AdminCreateProject provisions a control-plane project. Operator-only.
func (h *IdentityHandler) AdminCreateProject(
	ctx context.Context,
	req *connect.Request[identitypb.AdminCreateProjectRequest],
) (*connect.Response[identitypb.AdminCreateProjectResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	projectID, err := h.controlAdmin.AdminCreateProject(ctx, adminSecret(req.Header()), req.Msg.Name, req.Msg.StorageScopeId)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminCreateProjectResponse{ProjectId: projectID}), nil
}

// AdminCreateProjectCredential mints a project credential and returns the raw
// key exactly once. Operator-only.
func (h *IdentityHandler) AdminCreateProjectCredential(
	ctx context.Context,
	req *connect.Request[identitypb.AdminCreateProjectCredentialRequest],
) (*connect.Response[identitypb.AdminCreateProjectCredentialResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	minted, err := h.controlAdmin.AdminCreateProjectCredential(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.Kind)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminCreateProjectCredentialResponse{
		CredentialId: minted.ID,
		PublicId:     minted.PublicID,
		RawKey:       minted.RawKey,
	}), nil
}

// AdminAddProjectAuthDomain registers a serving hostname on a project,
// idempotently and seeded verified. Operator-only.
func (h *IdentityHandler) AdminAddProjectAuthDomain(
	ctx context.Context,
	req *connect.Request[identitypb.AdminAddProjectAuthDomainRequest],
) (*connect.Response[identitypb.AdminAddProjectAuthDomainResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	if err := h.controlAdmin.AdminAddProjectAuthDomain(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.Hostname, req.Msg.IsPrimary); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminAddProjectAuthDomainResponse{}), nil
}

// AddProjectAuthDomain registers a customer-owned serving hostname UNVERIFIED
// and returns its DNS TXT ownership challenge. Operator-only.
func (h *IdentityHandler) AddProjectAuthDomain(
	ctx context.Context,
	req *connect.Request[identitypb.AddProjectAuthDomainRequest],
) (*connect.Response[identitypb.AddProjectAuthDomainResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	reg, err := h.controlAdmin.AddProjectAuthDomain(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.Hostname, req.Msg.IsPrimary)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AddProjectAuthDomainResponse{
		Domain:   authDomainToProto(reg.Domain),
		TxtName:  reg.TXTName,
		TxtValue: reg.TXTValue,
	}), nil
}

// VerifyProjectAuthDomain checks the DNS TXT challenge and flips a custom
// auth-domain to verified (resolving). Operator-only.
func (h *IdentityHandler) VerifyProjectAuthDomain(
	ctx context.Context,
	req *connect.Request[identitypb.VerifyProjectAuthDomainRequest],
) (*connect.Response[identitypb.VerifyProjectAuthDomainResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	d, err := h.controlAdmin.VerifyProjectAuthDomain(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.Hostname)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.VerifyProjectAuthDomainResponse{
		Domain: authDomainToProto(d),
	}), nil
}

// ListProjectAuthDomains lists a project's auth-domains (verified and
// pending). Operator-only.
func (h *IdentityHandler) ListProjectAuthDomains(
	ctx context.Context,
	req *connect.Request[identitypb.ListProjectAuthDomainsRequest],
) (*connect.Response[identitypb.ListProjectAuthDomainsResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	domains, err := h.controlAdmin.ListProjectAuthDomains(ctx, adminSecret(req.Header()), req.Msg.ProjectId)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*identitypb.ProjectAuthDomain, 0, len(domains))
	for _, d := range domains {
		out = append(out, authDomainToProto(d))
	}
	return connect.NewResponse(&identitypb.ListProjectAuthDomainsResponse{Domains: out}), nil
}

// SetPrimaryAuthDomain promotes a VERIFIED custom auth-domain to the project's
// primary serving host, atomically demoting the current primary. Operator-only.
func (h *IdentityHandler) SetPrimaryAuthDomain(
	ctx context.Context,
	req *connect.Request[identitypb.SetPrimaryAuthDomainRequest],
) (*connect.Response[identitypb.SetPrimaryAuthDomainResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	d, err := h.controlAdmin.SetPrimaryAuthDomain(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.Hostname)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.SetPrimaryAuthDomainResponse{
		Domain: authDomainToProto(d),
	}), nil
}

// authDomainToProto maps a service auth-domain value to its proto message. A
// nil input yields nil (the field is simply omitted).
func authDomainToProto(d *service.AdminProjectAuthDomain) *identitypb.ProjectAuthDomain {
	if d == nil {
		return nil
	}
	return &identitypb.ProjectAuthDomain{
		Hostname:     d.Hostname,
		IsPrimary:    d.IsPrimary,
		VerifiedAtMs: d.VerifiedAtMs,
	}
}

// AdminCreateTenant provisions a tenant under a project. Operator-only.
func (h *IdentityHandler) AdminCreateTenant(
	ctx context.Context,
	req *connect.Request[identitypb.AdminCreateTenantRequest],
) (*connect.Response[identitypb.AdminCreateTenantResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	tenantID, err := h.controlAdmin.AdminCreateTenant(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.Name, req.Msg.PrimaryDomain)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminCreateTenantResponse{TenantId: tenantID}), nil
}

// AdminAddTenantAdmin bootstraps the first tenant administrator. Operator-only.
func (h *IdentityHandler) AdminAddTenantAdmin(
	ctx context.Context,
	req *connect.Request[identitypb.AdminAddTenantAdminRequest],
) (*connect.Response[identitypb.AdminAddTenantAdminResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	m, err := h.controlAdmin.AdminAddTenantAdmin(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.TenantId, req.Msg.UserId, req.Msg.Role)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminAddTenantAdminResponse{
		Membership: membershipToProto(m),
	}), nil
}

// UpsertLoginPolicy authors a claimed tenant's LoginPolicy (the policy the
// login path enforces). Operator-only.
func (h *IdentityHandler) UpsertLoginPolicy(
	ctx context.Context,
	req *connect.Request[identitypb.UpsertLoginPolicyRequest],
) (*connect.Response[identitypb.UpsertLoginPolicyResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	policy, err := h.controlAdmin.UpsertLoginPolicy(ctx, adminSecret(req.Header()), &service.LoginPolicy{
		ProjectID:                     req.Msg.ProjectId,
		TenantID:                      req.Msg.TenantId,
		AllowedMethods:                req.Msg.AllowedMethods,
		SSORequired:                   req.Msg.SsoRequired,
		SSOConnectionJSON:             req.Msg.SsoConnectionJson,
		Require2FA:                    req.Msg.Require_2Fa,
		PasswordMinLength:             int(req.Msg.PasswordMinLength),
		SessionIdleTimeoutSeconds:     req.Msg.SessionIdleTimeoutSeconds,
		SessionAbsoluteTimeoutSeconds: req.Msg.SessionAbsoluteTimeoutSeconds,
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.UpsertLoginPolicyResponse{
		Policy: loginPolicyToProto(policy),
	}), nil
}

// GetLoginPolicy reads a claimed tenant's LoginPolicy. The policy field is
// unset when none exists. Operator-only.
func (h *IdentityHandler) GetLoginPolicy(
	ctx context.Context,
	req *connect.Request[identitypb.GetLoginPolicyRequest],
) (*connect.Response[identitypb.GetLoginPolicyResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	policy, err := h.controlAdmin.GetLoginPolicy(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.GetLoginPolicyResponse{
		Policy: loginPolicyToProto(policy),
	}), nil
}

// DeleteLoginPolicy clears a claimed tenant's LoginPolicy (idempotent).
// Operator-only.
func (h *IdentityHandler) DeleteLoginPolicy(
	ctx context.Context,
	req *connect.Request[identitypb.DeleteLoginPolicyRequest],
) (*connect.Response[identitypb.DeleteLoginPolicyResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	if err := h.controlAdmin.DeleteLoginPolicy(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.TenantId); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.DeleteLoginPolicyResponse{}), nil
}

// UpsertProjectConfig replaces a project's config_json blob. Operator-only.
func (h *IdentityHandler) UpsertProjectConfig(
	ctx context.Context,
	req *connect.Request[identitypb.UpsertProjectConfigRequest],
) (*connect.Response[identitypb.UpsertProjectConfigResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	stored, err := h.controlAdmin.UpsertProjectConfig(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.ConfigJson)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.UpsertProjectConfigResponse{ConfigJson: stored}), nil
}

// GetProjectConfig reads a project's config_json blob. Operator-only.
func (h *IdentityHandler) GetProjectConfig(
	ctx context.Context,
	req *connect.Request[identitypb.GetProjectConfigRequest],
) (*connect.Response[identitypb.GetProjectConfigResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	stored, err := h.controlAdmin.GetProjectConfig(ctx, adminSecret(req.Header()), req.Msg.ProjectId)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.GetProjectConfigResponse{ConfigJson: stored}), nil
}

// AdminSetProjectOAuthProvider sets/rotates one of a project's OAuth providers,
// encrypting any plaintext secret server-side. The response redacts secrets.
// Operator-only.
func (h *IdentityHandler) AdminSetProjectOAuthProvider(
	ctx context.Context,
	req *connect.Request[identitypb.AdminSetProjectOAuthProviderRequest],
) (*connect.Response[identitypb.AdminSetProjectOAuthProviderResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	view, err := h.controlAdmin.AdminSetProjectOAuthProvider(ctx, adminSecret(req.Header()), req.Msg.ProjectId, oauthProviderInputFromProto(req.Msg.Config))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminSetProjectOAuthProviderResponse{
		Config: oauthProviderViewToProto(view),
	}), nil
}

// AdminDeleteProjectOAuthProvider removes one of a project's OAuth providers.
// Operator-only.
func (h *IdentityHandler) AdminDeleteProjectOAuthProvider(
	ctx context.Context,
	req *connect.Request[identitypb.AdminDeleteProjectOAuthProviderRequest],
) (*connect.Response[identitypb.AdminDeleteProjectOAuthProviderResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	if err := h.controlAdmin.AdminDeleteProjectOAuthProvider(ctx, adminSecret(req.Header()), req.Msg.ProjectId, req.Msg.Provider); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.AdminDeleteProjectOAuthProviderResponse{}), nil
}

// AdminListProjectOAuthProviders lists a project's configured OAuth providers
// with secrets redacted. Operator-only.
func (h *IdentityHandler) AdminListProjectOAuthProviders(
	ctx context.Context,
	req *connect.Request[identitypb.AdminListProjectOAuthProvidersRequest],
) (*connect.Response[identitypb.AdminListProjectOAuthProvidersResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	views, err := h.controlAdmin.AdminListProjectOAuthProviders(ctx, adminSecret(req.Header()), req.Msg.ProjectId)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*identitypb.ProjectOAuthProviderConfig, 0, len(views))
	for _, v := range views {
		out = append(out, oauthProviderViewToProto(v))
	}
	return connect.NewResponse(&identitypb.AdminListProjectOAuthProvidersResponse{Providers: out}), nil
}

// oauthProviderInputFromProto maps the write-side proto config (which carries
// plaintext secrets) to the service authoring input. A nil message yields a
// zero input, letting the service reject it with a clear "missing config" error.
func oauthProviderInputFromProto(c *identitypb.ProjectOAuthProviderConfig) *service.ProjectOAuthProviderInput {
	if c == nil {
		return nil
	}
	return &service.ProjectOAuthProviderInput{
		Provider:               c.Provider,
		ClientID:               c.ClientId,
		ClientSecret:           c.ClientSecret,
		NativeAudiences:        c.NativeAudiences,
		GoogleAuthorizationURL: c.GoogleAuthorizationUrl,
		GoogleTokenURL:         c.GoogleTokenUrl,
		GoogleJWKSURL:          c.GoogleJwksUrl,
		GoogleIssuer:           c.GoogleIssuer,
		MicrosoftTenantID:      c.MicrosoftTenantId,
		MicrosoftIssuerFormat:  c.MicrosoftIssuerFormat,
		AppleTeamID:            c.AppleTeamId,
		AppleKeyID:             c.AppleKeyId,
		ApplePrivateKey:        c.ApplePrivateKey,
		OIDCIssuer:             c.OidcIssuer,
		OIDCDiscoveryURL:       c.OidcDiscoveryUrl,
		OIDCScopes:             c.OidcScopes,
	}
}

// oauthProviderViewToProto maps a REDACTED service provider view to its proto
// message. Secret fields are never populated — only the has_* flags. A nil input
// yields nil.
func oauthProviderViewToProto(v *service.ProjectOAuthProviderView) *identitypb.ProjectOAuthProviderConfig {
	if v == nil {
		return nil
	}
	return &identitypb.ProjectOAuthProviderConfig{
		Provider:               v.Provider,
		ClientId:               v.ClientID,
		HasClientSecret:        v.HasClientSecret,
		NativeAudiences:        v.NativeAudiences,
		GoogleAuthorizationUrl: v.GoogleAuthorizationURL,
		GoogleTokenUrl:         v.GoogleTokenURL,
		GoogleJwksUrl:          v.GoogleJWKSURL,
		GoogleIssuer:           v.GoogleIssuer,
		MicrosoftTenantId:      v.MicrosoftTenantID,
		MicrosoftIssuerFormat:  v.MicrosoftIssuerFormat,
		AppleTeamId:            v.AppleTeamID,
		AppleKeyId:             v.AppleKeyID,
		HasPrivateKey:          v.HasPrivateKey,
		OidcIssuer:             v.OIDCIssuer,
		OidcDiscoveryUrl:       v.OIDCDiscoveryURL,
		OidcScopes:             v.OIDCScopes,
	}
}

// loginPolicyToProto maps a service LoginPolicy to its proto message. A nil
// input yields nil (the field is omitted — meaning "no policy set").
func loginPolicyToProto(p *service.LoginPolicy) *identitypb.LoginPolicy {
	if p == nil {
		return nil
	}
	return &identitypb.LoginPolicy{
		ProjectId:                     p.ProjectID,
		TenantId:                      p.TenantID,
		AllowedMethods:                p.AllowedMethods,
		SsoRequired:                   p.SSORequired,
		SsoConnectionJson:             p.SSOConnectionJSON,
		Require_2Fa:                   p.Require2FA,
		CreatedAtMs:                   p.CreatedAtMs,
		UpdatedAtMs:                   p.UpdatedAtMs,
		PasswordMinLength:             intToProtoInt32(p.PasswordMinLength),
		SessionIdleTimeoutSeconds:     p.SessionIdleTimeoutSeconds,
		SessionAbsoluteTimeoutSeconds: p.SessionAbsoluteTimeoutSeconds,
	}
}

// CreateFirstPlatformAdmin is the trust-on-first-use bootstrap of the first
// platform admin. It succeeds only while platform_admins is empty and is
// rejected (FailedPrecondition) once any admin exists. It stays zero-config
// only when no admin secret is set: when GATEWAY_ADMIN_API_SECRET is
// configured the presented X-Admin-Secret must match (like the other admin
// RPCs), and when GATEWAY_DISABLE_FIRST_ADMIN_BOOTSTRAP is true it is closed
// entirely. nil controlAdmin (memory, no control plane) yields Unimplemented.
func (h *IdentityHandler) CreateFirstPlatformAdmin(
	ctx context.Context,
	req *connect.Request[identitypb.CreateFirstPlatformAdminRequest],
) (*connect.Response[identitypb.CreateFirstPlatformAdminResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	admin, err := h.controlAdmin.CreateFirstPlatformAdmin(ctx, adminSecret(req.Header()), req.Msg.Email, req.Msg.Password)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CreateFirstPlatformAdminResponse{
		AdminId:           admin.ID,
		Email:             admin.Email,
		GeneratedPassword: admin.GeneratedPassword,
	}), nil
}
