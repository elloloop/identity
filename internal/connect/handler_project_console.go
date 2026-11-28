package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// The project console RPCs (ADR-0022) are called by a signed-in account of
// the deployment's own project, so the auth middleware has verified a user
// JWT before any of them runs and the handler reads the caller from the
// headers it injected. Who that caller may act for is the service's
// decision (service.ProjectConsoleService), not the handler's.
//
// h.console is nil unless the console is enabled on a build with a control
// plane, which yields Unimplemented for every one of them.

// WithProjectConsole sets the service behind the project console RPCs. A nil
// service leaves them Unimplemented.
func (h *IdentityHandler) WithProjectConsole(console *service.ProjectConsoleService) *IdentityHandler {
	h.console = console
	return h
}

// consoleCaller returns the authenticated caller of a console RPC, or the
// error that refuses the call: Unimplemented with no console, Unauthenticated
// with no session.
func (h *IdentityHandler) consoleCaller(headers headerReader) (string, error) {
	if h.console == nil {
		return "", connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	userID := authenticatedUserID(headers)
	if userID == "" {
		return "", toConnectError(service.ErrUnauthenticated)
	}
	return userID, nil
}

func consoleProjectToProto(p *service.MemberProject) *identitypb.ConsoleProject {
	return &identitypb.ConsoleProject{
		ProjectId:      p.ID,
		Name:           p.Name,
		Role:           p.Role,
		PublishableKey: p.PublishableKey,
		CreatedAt:      msToTimestamp(p.CreatedAtMs),
	}
}

// CreateProject creates a project the authenticated caller owns.
func (h *IdentityHandler) CreateProject(
	ctx context.Context,
	req *connect.Request[identitypb.CreateProjectRequest],
) (*connect.Response[identitypb.CreateProjectResponse], error) {
	userID, err := h.consoleCaller(req.Header())
	if err != nil {
		return nil, err
	}
	project, err := h.console.CreateProject(
		ctx, userID, authenticatedSignIn(req.Header()), req.Msg.GetName(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.CreateProjectResponse{Project: consoleProjectToProto(project)}), nil
}

// ListMyProjects lists the projects the authenticated caller manages.
func (h *IdentityHandler) ListMyProjects(
	ctx context.Context,
	req *connect.Request[identitypb.ListMyProjectsRequest],
) (*connect.Response[identitypb.ListMyProjectsResponse], error) {
	userID, err := h.consoleCaller(req.Header())
	if err != nil {
		return nil, err
	}
	projects, err := h.console.ListMyProjects(ctx, userID)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*identitypb.ConsoleProject, 0, len(projects))
	for _, p := range projects {
		out = append(out, consoleProjectToProto(p))
	}
	return connect.NewResponse(&identitypb.ListMyProjectsResponse{
		Projects:         out,
		CanCreateProject: h.console.SelfServiceProjects(),
	}), nil
}

// GetProjectSettings reads the member-editable part of a project's config.
func (h *IdentityHandler) GetProjectSettings(
	ctx context.Context,
	req *connect.Request[identitypb.GetProjectSettingsRequest],
) (*connect.Response[identitypb.GetProjectSettingsResponse], error) {
	userID, err := h.consoleCaller(req.Header())
	if err != nil {
		return nil, err
	}
	settings, version, err := h.console.GetProjectSettings(ctx, userID, req.Msg.GetProjectId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.GetProjectSettingsResponse{SettingsJson: settings, Version: version}), nil
}

// UpdateProjectSettings changes the member-editable part of a project's
// config.
func (h *IdentityHandler) UpdateProjectSettings(
	ctx context.Context,
	req *connect.Request[identitypb.UpdateProjectSettingsRequest],
) (*connect.Response[identitypb.UpdateProjectSettingsResponse], error) {
	userID, err := h.consoleCaller(req.Header())
	if err != nil {
		return nil, err
	}
	settings, version, err := h.console.UpdateProjectSettings(
		ctx, userID, authenticatedSignIn(req.Header()),
		req.Msg.GetProjectId(), req.Msg.GetSettingsJson(), req.Msg.GetExpectedVersion(),
		clientIP(req.Header()), clientUserAgent(req.Header()),
	)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.UpdateProjectSettingsResponse{SettingsJson: settings, Version: version}), nil
}
