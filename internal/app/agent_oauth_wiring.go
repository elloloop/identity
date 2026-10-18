package app

import (
	"context"
	"fmt"
	"net/http"

	"connectrpc.com/connect"

	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/app/ui"
	"github.com/elloloop/identity/internal/config"
	identityconnect "github.com/elloloop/identity/internal/connect"
	"github.com/elloloop/identity/internal/service"
)

func configureAgentOAuthSweep(sweep *sweeper, deps Deps) {
	if sweep != nil {
		if _, ok := deps.Repo.(service.AgentOAuthRepository); ok {
			sweep.agentOAuthSweep = func(ctx context.Context, beforeMs int64, limit int) error {
				return sweepAgentOAuth(ctx, deps.Repo, deps.Projects, deps.Config.DefaultProjectID, beforeMs, limit)
			}
		}
	}
}

func mountIdentityService(
	mux *http.ServeMux, deps Deps, authSvc *service.AuthService, handler *identityconnect.IdentityHandler, returnAllow service.ReturnAllowlist,
) error {
	connectOpts, err := buildConnectHandlerOptions(deps.Config)
	if err != nil {
		return fmt.Errorf("otelconnect interceptor: %w", err)
	}

	var agentOAuth *service.AgentOAuthService
	if deps.Config.AgentOAuthEnabled {
		agentOAuth, err = service.NewAgentOAuthService(authSvc, deps.Repo)
		if err != nil {
			return fmt.Errorf("agent OAuth: %w", err)
		}
	}
	handler.WithAgentOAuth(agentOAuth)
	if agentOAuth != nil {
		(&agentOAuthProtocol{service: agentOAuth, auth: authSvc, issuer: deps.Config.JWTIssuer}).register(mux)
		mux.Handle(agentOAuthConsentPath, ui.AgentConsentHandler(deps.Config, authSvc, returnAllow))
	}
	connectOpts = append(connectOpts, connect.WithConditionalHandlerOptions(func(spec connect.Spec) []connect.HandlerOption {
		switch spec.Procedure {
		case identityconnectgen.IdentityServiceIntrospectAgentMachineProcedure, identityconnectgen.IdentityServiceRegisterAgentMachineProcedure, identityconnectgen.IdentityServiceListAgentMachinesProcedure, identityconnectgen.IdentityServiceSelectAgentMachineAgentsProcedure, identityconnectgen.IdentityServiceRevokeAgentMachineProcedure, identityconnectgen.IdentityServiceExchangeAgentMachineCredentialProcedure, identityconnectgen.IdentityServiceListAgentMachineAgentsProcedure:
			return []connect.HandlerOption{connect.WithReadMaxBytes(config.AgentMachineRequestMaxBytes)}
		default:
			return nil
		}
	}))
	path, svcHandler := identityconnectgen.NewIdentityServiceHandler(handler, connectOpts...)
	mux.Handle(path, svcHandler)

	return nil
}
