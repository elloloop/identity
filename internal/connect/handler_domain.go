package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// CreateDomain registers a pending email domain on a tenant and returns the
// DNS TXT challenge the caller must publish. Available only on the postgres
// control-plane driver; nil service (memory) returns Unimplemented.
func (h *IdentityHandler) CreateDomain(
	ctx context.Context,
	req *connect.Request[identitypb.CreateDomainRequest],
) (*connect.Response[identitypb.CreateDomainResponse], error) {
	if h.domains == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	created, err := h.domains.CreateDomain(ctx, userID, req.Msg.TenantId, req.Msg.Domain, req.Msg.VerificationMethod)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CreateDomainResponse{
		Domain:      domainToProto(created.Domain),
		DnsTxtName:  created.TXTName,
		DnsTxtValue: created.TXTValue,
	}), nil
}

// VerifyDomain proves control of a pending domain, claiming its tenant and
// making the caller an owner on success.
func (h *IdentityHandler) VerifyDomain(
	ctx context.Context,
	req *connect.Request[identitypb.VerifyDomainRequest],
) (*connect.Response[identitypb.VerifyDomainResponse], error) {
	if h.domains == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	d, err := h.domains.VerifyDomain(ctx, userID, req.Msg.DomainId)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.VerifyDomainResponse{
		Domain: domainToProto(d),
	}), nil
}

// ListTenantDomains lists every domain bound to a tenant.
func (h *IdentityHandler) ListTenantDomains(
	ctx context.Context,
	req *connect.Request[identitypb.ListTenantDomainsRequest],
) (*connect.Response[identitypb.ListTenantDomainsResponse], error) {
	if h.domains == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	domains, err := h.domains.ListTenantDomains(ctx, userID, req.Msg.TenantId)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*identitypb.Domain, 0, len(domains))
	for _, d := range domains {
		out = append(out, domainToProto(d))
	}
	return connect.NewResponse(&identitypb.ListTenantDomainsResponse{
		Domains: out,
	}), nil
}

// domainToProto converts a service-layer Domain to the proto wire message.
func domainToProto(d *service.Domain) *identitypb.Domain {
	if d == nil {
		return nil
	}
	return &identitypb.Domain{
		Id:                 d.ID,
		TenantId:           d.TenantID,
		Domain:             d.Domain,
		VerificationMethod: d.VerificationMethod,
		Status:             d.Status,
		VerifiedAt:         msToTimestamp(d.VerifiedAtMs),
		CreatedAt:          msToTimestamp(d.CreatedAtMs),
		UpdatedAt:          msToTimestamp(d.UpdatedAtMs),
	}
}
