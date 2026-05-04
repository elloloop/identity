// Package app builds the identity service HTTP handler from injected
// dependencies. It is shared by the production binary (cmd/identity)
// and the integration test harness (tests/integration), so that both
// exercise the exact same wiring code: middleware chain, audit logger,
// service layer, and Connect-RPC handler registration.
package app

import (
	"net/http"

	"go.uber.org/zap"

	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/config"
	identityconnect "github.com/elloloop/identity/internal/connect"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt"
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
}

// New builds the full HTTP handler stack: middleware chain wrapping
// the Connect-RPC handler. The returned handler is ready to be served
// via http.Server (or httptest.NewServer in tests).
func New(deps Deps) http.Handler {
	logger := deps.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	auditLog := audit.NewLogger(deps.DB, deps.Config.DefaultTenantID, logger)

	mailer := deps.EmailTransport
	if mailer == nil {
		mailer = buildEmailTransport(deps.Config, logger)
	}

	authSvc := service.NewAuthService(deps.Repo, deps.Config, deps.KeyRing, deps.Passkeys, auditLog, deps.TOTPKey, mailer, logger)
	adminSvc := service.NewAdminService(deps.DB, deps.Config.DefaultTenantID, auditLog, deps.Config, mailer, logger)
	groupsSvc := service.NewGroupService(deps.DB, deps.Config.DefaultTenantID, auditLog, logger)
	helpSvc := service.NewHelpService(deps.DB, deps.Config.DefaultTenantID, auditLog, logger)
	profileSvc := service.NewProfileService(deps.DB, deps.Config.DefaultTenantID, auditLog, logger)

	handler := identityconnect.NewIdentityHandler(authSvc, adminSvc, groupsSvc, helpSvc, profileSvc)

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
