// Package app builds the identity service HTTP handler from injected
// dependencies. It is shared by the production binary (cmd/identity)
// and the integration test harness (tests/integration), so that both
// exercise the exact same wiring code: middleware chain, audit logger,
// service layer, and Connect-RPC handler registration.
package app

import (
	"context"
	"fmt"
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

	// TOTPRecoveryPepper is the HMAC-SHA-256 key used to hash and
	// verify recovery codes. Must be >= totp.MinRecoveryPepperBytes
	// bytes long; the binary refuses to start otherwise.
	TOTPRecoveryPepper []byte

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
// the Connect-RPC handler. The returned shutdown func must be called
// during graceful termination so background workers (audit flusher etc.)
// drain cleanly. Configuration errors (e.g. invalid CORS origins) are
// returned without starting the audit flusher.
func New(deps Deps) (http.Handler, func(), error) {
	noopStop := func() {}
	logger := deps.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	allowedOrigins, err := middleware.ParseAllowedOrigins(deps.Config.AllowedOrigins, true)
	if err != nil {
		return nil, noopStop, fmt.Errorf("cors config invalid: %w", err)
	}
	logger.Info("cors_allowed_origins", zap.Strings("origins", allowedOrigins))

	// Surface the EntDB schema-apply gap loudly at boot so operators
	// see exactly which node types identity expects the database to
	// know about. See internal/app/schema.go for why this only logs.
	if err := applyOrLogSchemaGap(context.Background(), deps.DB, logger); err != nil {
		logger.Error("schema_descriptor_invalid", zap.Error(err))
	}

	auditLog := audit.NewLogger(deps.DB, deps.Config.DefaultTenantID, logger)
	// Move audit writes off the auth hot path. Drops are counted and
	// surfaced via auditLog.DroppedCount(). Caller must invoke the
	// returned shutdown func to drain pending writes on termination.
	stopAudit := auditLog.StartAsync(deps.Config.AuditQueueSize)

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
		auditLog, deps.TOTPKey, deps.TOTPRecoveryPepper, mailer, logger,
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
	chain = middleware.AuthMiddleware(deps.KeyRing, deps.Config.DefaultTenantID, deps.Config.JWTAudience, deps.Config.JWTRequireAudience)(chain)
	chain = middleware.JWKSMiddleware(deps.KeyRing)(chain)
	chain = middleware.HealthMiddleware(chain)
	chain = middleware.CORSMiddleware(allowedOrigins)(chain)
	chain = middleware.LoggingMiddleware(logger)(chain)
	return chain, stopAudit, nil
}
