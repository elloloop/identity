package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
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

// CreateFirstPlatformAdmin is the zero-config bootstrap of the first platform
// admin. Unlike the other Admin RPCs it reads NO admin secret: it succeeds
// only while platform_admins is empty and is rejected (FailedPrecondition)
// once any admin exists. nil controlAdmin (memory, no control plane)
// yields Unimplemented.
func (h *IdentityHandler) CreateFirstPlatformAdmin(
	ctx context.Context,
	req *connect.Request[identitypb.CreateFirstPlatformAdminRequest],
) (*connect.Response[identitypb.CreateFirstPlatformAdminResponse], error) {
	if h.controlAdmin == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	admin, err := h.controlAdmin.CreateFirstPlatformAdmin(ctx, req.Msg.Email, req.Msg.Password)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CreateFirstPlatformAdminResponse{
		AdminId:           admin.ID,
		Email:             admin.Email,
		GeneratedPassword: admin.GeneratedPassword,
	}), nil
}
