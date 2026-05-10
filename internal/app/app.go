// Package app builds the identity service HTTP handler from injected
// dependencies. It is shared by the production binary (cmd/identity)
// and the integration test harness (tests/integration), so that both
// exercise the exact same wiring code: middleware chain, audit logger,
// service layer, and Connect-RPC handler registration.
package app

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/config"
	identityconnect "github.com/elloloop/identity/internal/connect"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/idv"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
)

// Deps groups the injectable dependencies required to build the
// identity HTTP handler. It lets the production main.go pass real
// adapters and the integration test harness pass in-memory fakes,
// without duplicating the wiring code.
type Deps struct {
	Config   *config.Config
	Logger   *zap.Logger
	KeyRing  *jwt.KeyRing
	Repo     service.Repository
	DB       service.DB
	Passkeys *passkeys.WebAuthnService
	TOTPKey  []byte

	// EmailTransport delivers outbound mail. If nil, New constructs a
	// transport from cfg via buildEmailTransport (so production code
	// only needs to populate this when a test wants a custom recorder).
	EmailTransport email.Transport

	// OAuthRegistry holds the per-provider Exchangers used for OAuth
	// login. May be nil — in that case OAuthLogin returns
	// ErrOAuthDisabled. When nil, New builds a registry from the
	// config's GATEWAY_*_CLIENT_ID/SECRET env vars (only providers
	// with both credentials set are registered).
	OAuthRegistry *oauth.Registry

	// IDVProvider drives identity-verification (document + selfie).
	// May be nil — in that case BeginIdentityVerification returns
	// CodeUnimplemented. Production deployments wire an Azure or
	// other real provider; tests typically pass an idv.StubProvider.
	IDVProvider idv.Provider
}

// New builds the full HTTP handler stack: middleware chain wrapping
// the Connect-RPC handler. The returned handler is ready to be served
// via http.Server (or httptest.NewServer in tests).
func New(deps Deps) http.Handler {
	logger := deps.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	// Surface the EntDB schema-apply gap loudly at boot so operators
	// see exactly which node types identity expects the database to
	// know about. See internal/app/schema.go for why this only logs.
	if err := applyOrLogSchemaGap(context.Background(), deps.DB, logger); err != nil {
		logger.Error("schema_descriptor_invalid", zap.Error(err))
	}

	auditLog := audit.NewLogger(deps.DB, deps.Config.DefaultTenantID, logger)

	mailer := deps.EmailTransport
	if mailer == nil {
		mailer = buildEmailTransport(deps.Config, logger)
	}

	oauthRegistry := deps.OAuthRegistry
	if oauthRegistry == nil {
		oauthRegistry = buildOAuthRegistry(deps.Config, logger)
	}

	authSvc := service.NewAuthServiceWithOAuth(
		deps.Repo, deps.Config, deps.KeyRing, deps.Passkeys,
		auditLog, deps.TOTPKey, mailer, logger,
		oauthRegistry,
	)
	adminSvc := service.NewAdminService(deps.DB, deps.Config.DefaultTenantID, auditLog, deps.Config, mailer, logger)
	groupsSvc := service.NewGroupService(deps.DB, deps.Config.DefaultTenantID, auditLog, logger)
	helpSvc := service.NewHelpService(deps.DB, deps.Config.DefaultTenantID, auditLog, logger)
	profileSvc := service.NewProfileService(deps.DB, deps.Config.DefaultTenantID, auditLog, logger)

	var idvSvc *service.IdentityVerificationService
	if deps.IDVProvider != nil {
		idvSvc = service.NewIdentityVerificationService(
			deps.Repo, deps.IDVProvider, deps.Config.DefaultTenantID, logger,
		)
	}

	handler := identityconnect.NewIdentityHandler(authSvc, adminSvc, groupsSvc, helpSvc, profileSvc, idvSvc, deps.Config)

	mux := http.NewServeMux()
	path, svcHandler := identityconnectgen.NewIdentityServiceHandler(handler)
	mux.Handle(path, svcHandler)

	// Order (outermost runs first on request path):
	//   logging → CORS → health → JWKS → auth → Connect handler
	var chain http.Handler = mux
	chain = middleware.AuthMiddleware(deps.KeyRing, deps.Config.DefaultTenantID)(chain)
	chain = middleware.JWKSMiddleware(deps.KeyRing)(chain)
	chain = middleware.HealthMiddleware(chain)
	chain = middleware.CORSMiddleware(deps.Config.AllowedOrigins)(chain)
	chain = middleware.LoggingMiddleware(logger)(chain)
	return chain
}
