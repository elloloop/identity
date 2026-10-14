package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

func oauthRegistrationFromProto(in *identitypb.OAuthClientRegistration) *service.OAuthClientRegistration {
	if in == nil {
		return nil
	}
	out := &service.OAuthClientRegistration{Name: in.GetName(), RedirectURIs: in.GetRedirectUris(), GrantTypes: in.GetGrantTypes(), Disabled: in.GetDisabled()}
	for _, resource := range in.GetResources() {
		out.Resources = append(out.Resources, service.OAuthResourceBounds{Resource: resource.GetResource(), Scopes: resource.GetScopes()})
	}
	return out
}

func oauthClientToProto(in *service.OAuthClient) *identitypb.OAuthClient {
	registration := &identitypb.OAuthClientRegistration{Name: in.Registration.Name, RedirectUris: in.Registration.RedirectURIs, GrantTypes: in.Registration.GrantTypes, Disabled: in.Registration.Disabled}
	for _, resource := range in.Registration.Resources {
		registration.Resources = append(registration.Resources, &identitypb.OAuthResourceBounds{Resource: resource.Resource, Scopes: resource.Scopes})
	}
	return &identitypb.OAuthClient{ClientId: in.ID, Kind: identitypb.OAuthClientKind_O_AUTH_CLIENT_KIND_NATIVE_PUBLIC, Registration: registration, Revision: in.Revision, CreatedAtMs: in.CreatedAt, UpdatedAtMs: in.UpdatedAt}
}

func (h *IdentityHandler) CreateOAuthClient(ctx context.Context, req *connect.Request[identitypb.CreateOAuthClientRequest]) (*connect.Response[identitypb.CreateOAuthClientResponse], error) {
	client, err := h.auth.CreateOAuthClient(ctx, authenticatedUserID(req.Header()), oauthRegistrationFromProto(req.Msg.GetRegistration()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CreateOAuthClientResponse{Client: oauthClientToProto(client)}), nil
}

func (h *IdentityHandler) GetOAuthClient(ctx context.Context, req *connect.Request[identitypb.GetOAuthClientRequest]) (*connect.Response[identitypb.GetOAuthClientResponse], error) {
	client, err := h.auth.GetOAuthClient(ctx, authenticatedUserID(req.Header()), req.Msg.GetClientId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.GetOAuthClientResponse{Client: oauthClientToProto(client)}), nil
}

func (h *IdentityHandler) UpdateOAuthClient(ctx context.Context, req *connect.Request[identitypb.UpdateOAuthClientRequest]) (*connect.Response[identitypb.UpdateOAuthClientResponse], error) {
	client, err := h.auth.UpdateOAuthClient(ctx, authenticatedUserID(req.Header()), req.Msg.GetClientId(), req.Msg.GetExpectedRevision(), oauthRegistrationFromProto(req.Msg.GetRegistration()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.UpdateOAuthClientResponse{Client: oauthClientToProto(client)}), nil
}

func (h *IdentityHandler) ListOAuthClients(ctx context.Context, req *connect.Request[identitypb.ListOAuthClientsRequest]) (*connect.Response[identitypb.ListOAuthClientsResponse], error) {
	clients, err := h.auth.ListOAuthClients(ctx, authenticatedUserID(req.Header()), req.Msg.GetAfterClientId(), int(req.Msg.GetLimit()))
	if err != nil {
		return nil, toConnectError(err)
	}
	out := &identitypb.ListOAuthClientsResponse{}
	for _, client := range clients {
		out.Clients = append(out.Clients, oauthClientToProto(client))
	}
	return connect.NewResponse(out), nil
}
