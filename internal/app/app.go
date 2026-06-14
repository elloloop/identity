// Package app builds the identity service HTTP handler from injected
// dependencies. It is shared by the production binary (cmd/identity)
// and the integration test harness (tests/integration), so that both
// exercise the exact same wiring code: middleware chain, audit logger,
// service layer, and Connect-RPC handler registration.
package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/app/ui"
	"github.com/elloloop/identity/internal/config"
	identityconnect "github.com/elloloop/identity/internal/connect"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/observability"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/captcha"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/idv"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/sms"
)

// Deps groups the injectable dependencies required to build the
// identity HTTP handler. It lets the production main.go pass real
// adapters and the integration test harness pass in-memory fakes,
// without duplicating the wiring code.
type Deps struct {
	Config   *config.Config
	Logger   *zap.Logger
	Signer   jwt.Signer
	Repo     service.Repository
	DB       service.DB
	Passkeys *passkeys.WebAuthnService
	TOTPKey  []byte

	// TenantAdmin is the cross-tenant admin handle backing the
	// `mode=multi` OrganizationSignup RPC. Required when
	// Config.IdentityMode == "multi"; ignored in single mode. The
	// production binary wires repo.NewTenantAdmin(entdbClient);
	// integration tests pass a fake.
	TenantAdmin service.TenantAdmin

	// RepositoryForTenant is the factory OrganizationSignup uses to
	// obtain a Repository scoped to the freshly-created tenant. When
	// nil, the handler treats `mode=multi` as not yet wired and
	// returns CodeUnimplemented. The production binary wires a closure
	// over the entdb client; tests pass a closure returning an
	// in-memory Repo keyed on tenant id.
	RepositoryForTenant service.RepositoryForTenant

	// ProjectResolver resolves a request's control-plane project from its
	// credential key or Host header (see middleware.NewProjectResolver).
	// Non-nil only for the postgres driver; when nil the project-resolution
	// middleware pins every request to the configured default project. The
	// production binary wires the postgres control-plane store; tests pass
	// a fake or nil.
	ProjectResolver service.ProjectResolver

	// TenantAutoFormer auto-forms a company tenant from a new user's email
	// domain at signup. Non-nil only for the postgres driver (the only one
	// with a governance plane); when nil, signup does not auto-form tenants.
	TenantAutoFormer service.TenantAutoFormStore

	// DomainStore, TenantStore and MembershipStore back the tenant
	// domain-verification RPCs (CreateDomain / VerifyDomain /
	// ListTenantDomains). All three are non-nil ONLY for the postgres
	// driver (the only one with a governance plane); when any is nil the
	// DomainService is not constructed and those RPCs return Unimplemented.
	DomainStore     service.DomainStore
	TenantStore     service.TenantStore
	MembershipStore service.MembershipStore

	// TOTPRecoveryPepper is the HMAC-SHA-256 key used to hash and
	// verify recovery codes. Must be >= totp.MinRecoveryPepperBytes
	// bytes long; the binary refuses to start otherwise.
	TOTPRecoveryPepper []byte

	// EmailTransport delivers outbound mail. If nil, New constructs a
	// transport from cfg via buildEmailTransport (so production code
	// only needs to populate this when a test wants a custom recorder).
	EmailTransport email.Transport

	// SMSSender delivers outbound SMS for phone verification. If nil, New
	// constructs a sender from cfg via buildSMSSender — a log-only sender
	// when GATEWAY_SMS_ENABLED is false, otherwise the configured
	// provider (Twilio / SNS / Azure).
	SMSSender sms.Sender

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

	// CaptchaVerifier gates the unauthenticated auth endpoints. May be
	// nil — in that case New builds one from Config (the no-op verifier
	// when CAPTCHA is disabled). Tests inject a fake to drive pass/fail
	// without network calls.
	CaptchaVerifier captcha.Verifier

	// MetricsRegistry is the Prometheus registry the server records
	// RED metrics into. May be nil — in that case the default
	// registry is used (which is what production wants). Tests pass an
	// isolated registry so they can read counters without colliding
	// with other tests in the same process.
	MetricsRegistry prometheus.Registerer
}

// Built is the result of New: the assembled identity service, ready to
// mount and run. It separates construction (no goroutines) from the
// background-worker lifecycle so the embedding consumer — the container
// binary or a host server — controls when workers run via Start/Stop.
//
//   - Handler is the full middleware chain wrapping the Connect-RPC
//     handler; mount it on any HTTP/2 (or h2c) server.
//   - ConnectHandler is the Connect service implementation. The native
//     gRPC bridge registers against this so both mount surfaces share
//     one service-layer wiring.
//   - Start launches the background workers (audit flusher, sweeper);
//     it is idempotent. Stop drains them; safe to call multiple times.
type Built struct {
	Handler        http.Handler
	ConnectHandler *identityconnect.IdentityHandler

	startOnce sync.Once
	stopOnce  sync.Once
	startWork func()
	stopWork  func()
}

// Start launches the background workers. Calling it more than once is a
// no-op. It is separate from New so the audit flusher and sweeper
// goroutines never start until the consumer is ready to run them.
func (b *Built) Start() {
	b.startOnce.Do(b.startWork)
}

// Stop drains the background workers. Safe to call multiple times and
// safe to call without a preceding Start.
func (b *Built) Stop() {
	b.stopOnce.Do(b.stopWork)
}

// buildRateLimits maps the unauthenticated, abuse-prone RPC paths to
// per-IP fixed-window limiters from config. The window falls back to one
// minute when unset. Extracted from New so the wiring (which path gets
// which quota) is unit-testable without standing up the whole app.
func buildRateLimits(cfg *config.Config) []middleware.PathLimit {
	window := time.Duration(cfg.RateLimitWindowSeconds) * time.Second
	if window <= 0 {
		window = time.Minute
	}
	return []middleware.PathLimit{
		{
			PathPrefix: "/identity.IdentityService/PasswordSignup", Tag: "signup",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitSignupPerIP, 0),
		},
		{
			// OrganizationSignup is an unauthenticated entry point that
			// provisions a whole tenant — share the per-IP signup quota
			// so a single source can't carve out tenants at signup speed.
			PathPrefix: "/identity.IdentityService/OrganizationSignup", Tag: "org_signup",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitSignupPerIP, 0),
		},
		{
			PathPrefix: "/identity.IdentityService/PasswordLogin", Tag: "login",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitLoginPerIP, 0),
		},
		{
			PathPrefix: "/identity.IdentityService/RequestPasswordReset", Tag: "reset",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitResetPerIP, 0),
		},
		{
			PathPrefix: "/identity.IdentityService/SendEmailVerification", Tag: "verify",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitVerifyPerIP, 0),
		},
		{
			// Passwordless OTP request: unauthenticated, sends an email.
			// Tight per-IP quota so a single source can't pump codes at a
			// victim inbox (the per-email cooldown is the second layer).
			PathPrefix: "/identity.IdentityService/RequestEmailLoginCode", Tag: "passwordless_code",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitPasswordlessPerIP, 0),
		},
		{
			// Passwordless magic-link request: same shape, same quota.
			PathPrefix: "/identity.IdentityService/RequestMagicLink", Tag: "passwordless_link",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitPasswordlessPerIP, 0),
		},
		{
			// Phone-verification OTP request: authenticated, but each call
			// sends an SMS, so a tight per-IP quota bounds cost/abuse (the
			// per-user cooldown is the second layer).
			PathPrefix: "/identity.IdentityService/RequestPhoneVerification", Tag: "phone_verify",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitPhonePerIP, 0),
		},
		{
			PathPrefix: "/identity.IdentityService/BeginOAuthLogin", Tag: "oauth_begin",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitLoginPerIP, 0),
		},
		{
			PathPrefix: "/identity.IdentityService/BeginPasskeyLogin", Tag: "passkey_begin",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitLoginPerIP, 0),
		},
		{
			PathPrefix: "/identity.IdentityService/VerifyTotp", Tag: "totp_verify",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitLoginPerIP, 0),
		},
	}
}

// New assembles the identity service from injected dependencies. It
// builds the middleware chain, the Connect-RPC service handler, and the
// background workers — but does NOT start the workers; the caller starts
// them with (*Built).Start once it is ready to serve, and drains them
// with (*Built).Stop on shutdown. Configuration errors (e.g. invalid
// CORS origins) are returned before any worker is constructed.
func New(deps Deps) (*Built, error) {
	logger := deps.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	// Validate config invariants that can't be expressed as per-field
	// defaults (most importantly the mode=ttl access-token TTL cap).
	// Fail fast before any goroutines start so a misconfigured deploy
	// never serves a single request.
	if err := deps.Config.Validate(); err != nil {
		return nil, err
	}
	if err := validateIdentityMode(deps, logger); err != nil {
		return nil, err
	}

	allowedOrigins, err := middleware.ParseAllowedOrigins(deps.Config.AllowedOrigins, true)
	if err != nil {
		return nil, fmt.Errorf("cors config invalid: %w", err)
	}
	logger.Info("cors_allowed_origins", zap.Strings("origins", allowedOrigins))

	trustedProxies, err := middleware.ParseTrustedProxies(deps.Config.TrustedProxies)
	if err != nil {
		logger.Error("trusted_proxies_invalid", zap.Error(err))
	}
	rateLimits := buildRateLimits(deps.Config)

	// Surface the EntDB schema-apply gap loudly at boot so operators
	// see exactly which node types identity expects the database to
	// know about. See internal/app/schema.go for why this only logs.
	if err := applyOrLogSchemaGap(context.Background(), deps.DB, logger); err != nil {
		logger.Error("schema_descriptor_invalid", zap.Error(err))
	}

	auditLog := audit.NewLogger(deps.DB, deps.Config.DefaultTenantID, logger)

	// Garbage-collection sweeper for expired ephemeral rows (#94).
	// Disabled when SweeperIntervalSeconds <= 0 — deployers who
	// already run their own GC, and the unit-test harness, both
	// flip it off via GATEWAY_SWEEPER_INTERVAL_SECONDS=0.
	sweep := newSweeper(
		deps.Repo,
		deps.Config.SweeperIntervalSeconds,
		deps.Config.SweeperBatchSize,
		deps.Config.SweeperGraceSeconds,
		logger,
	)

	// Background-worker lifecycle. The audit flusher and sweeper do NOT
	// start in New — they start when the consumer calls (*Built).Start,
	// so an embedding host controls when goroutines run, and drain when
	// it calls (*Built).Stop. Until Start runs, audit writes happen
	// synchronously on the calling goroutine (audit.Logger falls back to
	// sync mode), so a never-started Built is still correct, just slower.
	var stopAudit, stopSweeper func()
	startWork := func() {
		// Move audit writes off the auth hot path. Drops are counted and
		// surfaced via auditLog.DroppedCount().
		stopAudit = auditLog.StartAsync(deps.Config.AuditQueueSize)
		if sweep != nil {
			stopSweeper = sweep.start()
		}
	}
	stopWork := func() {
		if stopSweeper != nil {
			stopSweeper()
		}
		if stopAudit != nil {
			stopAudit()
		}
	}

	// Session cache + metric for mode=session. mode=ttl returns a nil
	// cache (and the middleware wrapper falls back to the zero-cost
	// AuthMiddleware). The Repository wrapper invalidates the cache on
	// same-process revokes so a forced revoke is visible on the very
	// next request rather than at the next TTL boundary.
	var sessionCache *middleware.SessionCache
	repo := deps.Repo
	if deps.Config.RevocationMode == config.RevocationModeSession {
		sessionMetrics, err := middleware.NewSessionMetrics(deps.MetricsRegistry)
		if err != nil {
			return nil, fmt.Errorf("session metrics: %w", err)
		}
		sessionCache = middleware.NewSessionCache(repo, deps.Config.SessionCacheTTL(), sessionMetrics)
		repo = middleware.WrapSessionRepository(repo, sessionCache)
	}

	mailer := deps.EmailTransport
	if mailer == nil {
		mailer = buildEmailTransport(deps.Config, logger)
	}
	mailer = observability.WrapMailer(mailer)

	smsSender := deps.SMSSender
	if smsSender == nil {
		smsSender, err = buildSMSSender(deps.Config, logger)
		if err != nil {
			return nil, fmt.Errorf("sms sender: %w", err)
		}
	}

	oauthRegistry := deps.OAuthRegistry
	if oauthRegistry == nil {
		oauthRegistry = buildOAuthRegistry(deps.Config, logger)
	}
	oauthRegistry = wrapOAuthRegistry(oauthRegistry)

	authSvc := service.NewAuthServiceWithOAuth(
		repo, deps.Config, deps.Signer, deps.Passkeys,
		auditLog, deps.TOTPKey, deps.TOTPRecoveryPepper, mailer, smsSender, logger,
		oauthRegistry,
	).WithTenantAutoFormer(deps.TenantAutoFormer)
	adminSvc := service.NewAdminService(repo, deps.DB, deps.Config.DefaultTenantID, auditLog, deps.Config, mailer, logger)
	groupsSvc := service.NewGroupService(deps.DB, deps.Config.DefaultTenantID, auditLog, logger)
	helpSvc := service.NewHelpService(deps.DB, deps.Config.DefaultTenantID, auditLog, logger)
	profileSvc := service.NewProfileService(repo, deps.DB, deps.Config.DefaultTenantID, auditLog, logger)

	var idvSvc *service.IdentityVerificationService
	if deps.IDVProvider != nil {
		idvSvc = service.NewIdentityVerificationService(
			repo, observability.WrapIDVProvider(deps.IDVProvider), deps.Config.DefaultTenantID, logger,
		)
	}

	captchaVerifier := deps.CaptchaVerifier
	if captchaVerifier == nil {
		captchaVerifier, err = buildCaptchaVerifier(deps.Config, logger)
		if err != nil {
			return nil, fmt.Errorf("captcha verifier: %w", err)
		}
	}

	orgSignupSvc := buildOrganizationSignupService(deps, auditLog, logger)
	domainSvc := buildDomainService(deps, logger)
	handler := identityconnect.NewIdentityHandler(authSvc, adminSvc, groupsSvc, helpSvc, profileSvc, idvSvc, orgSignupSvc, domainSvc, captchaVerifier, deps.Config)

	connectOpts, err := buildConnectHandlerOptions(deps.Config)
	if err != nil {
		return nil, fmt.Errorf("otelconnect interceptor: %w", err)
	}

	mux := http.NewServeMux()
	path, svcHandler := identityconnectgen.NewIdentityServiceHandler(handler, connectOpts...)
	mux.Handle(path, svcHandler)

	// Default auth UI (login/signup)
	mux.Handle("/auth/", ui.Handler())

	// Browser-facing hosted OAuth routes (#126). Registered only when
	// GATEWAY_OAUTH_ALLOWED_RETURN_URLS is non-empty; the headless
	// BeginOAuthLogin / OAuthLogin RPCs work regardless.
	returnAllow := service.ParseReturnAllowlist(deps.Config.OAuthAllowedReturnURLs)
	if returnAllow.Enabled() {
		logger.Info("oauth_hosted_flow_enabled", zap.Strings("allowed_return_urls", returnAllow.Entries()))
	} else {
		logger.Info("oauth_hosted_flow_disabled",
			zap.String("hint", "set GATEWAY_OAUTH_ALLOWED_RETURN_URLS to enable GET /oauth/start + /oauth/callback"))
	}
	(&hostedOAuthHandler{auth: authSvc, allowlist: returnAllow, logger: logger}).register(mux)

	rpcMetrics, err := middleware.NewRPCMetrics(deps.MetricsRegistry)
	if err != nil {
		return nil, fmt.Errorf("rpc metrics: %w", err)
	}

	// In mode=single every token's "tenant" claim must equal
	// DefaultTenantID, so the auth middleware pins it. In mode=multi
	// tokens carry per-tenant claims (the org slug), so the auth
	// middleware can't pin a single tenant — the TenantResolver
	// middleware cross-checks the claim against the resolved tenant
	// instead. See docs/IDENTITY.md decision log on tenant resolution.
	authExpectedTenant := deps.Config.DefaultTenantID
	if deps.Config.IsMultiMode() {
		authExpectedTenant = ""
	}

	// Order (outermost runs first on request path):
	//   logging → recover → CORS → health → client-IP → rate-limit → JWKS → project → auth → project-guard → tenant → metrics → Connect
	// client-IP must precede rate-limit (the limiter keys on the
	// resolved IP) and health must precede client-IP so liveness probes
	// from kubelets cannot be rate-limited. The project resolver sits just
	// outside auth so the resolved project is available to auth/tenant and
	// the service layer (it does not depend on the authenticated user — it
	// keys on the credential header or Host). The tenant resolver sits
	// just inside auth so it can read the verified user-id / tenant
	// headers, and just outside metrics so the resolved-tenant rejection
	// is counted. In mode=single the tenant resolver is an identity
	// pass-through; the project resolver pins the default project.
	// metrics sits just outside the Connect mux so it observes every
	// RPC's final status, including any failure synthesized by the
	// otelconnect interceptor.
	var chain http.Handler = mux
	chain = middleware.MetricsMiddleware(rpcMetrics)(chain)
	chain = middleware.NewTenantResolver(deps.Config, deps.RepositoryForTenant, logger)(chain)
	// Project-scope guard runs just after auth (which surfaces the verified
	// project) and before tenant resolution, rejecting an access token
	// replayed across projects.
	chain = middleware.NewProjectScopeGuard()(chain)
	chain = middleware.SessionAuthMiddleware(
		deps.Signer, authExpectedTenant, deps.Config.JWTAudience,
		deps.Config.JWTRequireAudience, sessionCache,
	)(chain)
	chain = middleware.NewProjectResolver(
		deps.Config.DefaultProjectID, deps.Config.DefaultTenantID,
		deps.Config.DefaultPrimaryAuthDomain(), deps.ProjectResolver, logger,
	)(chain)
	chain = middleware.JWKSMiddleware(deps.Signer)(chain)
	chain = middleware.RateLimitMiddleware(rateLimits, logger)(chain)
	chain = middleware.ClientIPMiddleware(trustedProxies)(chain)
	chain = middleware.HealthMiddleware(newDBReadinessProbe(deps.DB), chain)
	chain = middleware.CORSMiddleware(allowedOrigins)(chain)
	chain = middleware.RecoverMiddleware(logger)(chain)
	chain = middleware.LoggingMiddleware(logger)(chain)

	return &Built{
		Handler:        chain,
		ConnectHandler: handler,
		startWork:      startWork,
		stopWork:       stopWork,
	}, nil
}

// buildConnectHandlerOptions returns the otelconnect interceptor
// (when OTel is enabled) plus any future Connect-level options. When
// OTel is disabled the function returns an empty slice — no
// interceptor is added, so the Connect server's hot path has zero
// overhead beyond the no-op tracer/meter calls inside the runtime.
//
// Prometheus RED metrics live in MetricsMiddleware (one mechanism,
// not two). We disable otelconnect's metric emitter so the two
// pipelines don't double-count.
func buildConnectHandlerOptions(cfg *config.Config) ([]connect.HandlerOption, error) {
	if cfg == nil || !cfg.OTelEnabled {
		return nil, nil
	}
	interceptor, err := otelconnect.NewInterceptor(otelconnect.WithoutMetrics())
	if err != nil {
		return nil, err
	}
	return []connect.HandlerOption{connect.WithInterceptors(interceptor)}, nil
}

// validateIdentityMode enforces the per-deployment mode invariants at
// boot. mode=single requires a DefaultTenantID (the bootstrap tenant
// it pins all signups to). mode=multi requires the TenantAdmin and
// RepositoryForTenant wiring so OrganizationSignup is actually
// reachable; unrecognised modes are rejected outright to keep the
// auth-surface reasoning unambiguous (decision log §1).
func validateIdentityMode(deps Deps, logger *zap.Logger) error {
	if deps.Config == nil {
		return errors.New("identity mode: nil config")
	}
	mode := deps.Config.IdentityMode
	switch mode {
	case config.IdentityModeSingle:
		if deps.Config.DefaultTenantID == "" {
			return errors.New("identity mode=single requires GATEWAY_DEFAULT_TENANT_ID")
		}
		logger.Info("identity_mode_selected", zap.String("mode", mode), zap.String("default_tenant_id", deps.Config.DefaultTenantID))
		return nil
	case config.IdentityModeMulti:
		if deps.TenantAdmin == nil || deps.RepositoryForTenant == nil {
			return errors.New("identity mode=multi requires TenantAdmin and RepositoryForTenant")
		}
		logger.Info("identity_mode_selected", zap.String("mode", mode))
		return nil
	default:
		return fmt.Errorf("identity mode: unknown value %q (expected %q or %q)",
			mode, config.IdentityModeSingle, config.IdentityModeMulti)
	}
}

// buildOrganizationSignupService returns the wired
// OrganizationSignupService in `mode=multi`, or nil in `mode=single`.
// The Connect handler treats nil as "disabled" and returns
// CodeUnimplemented (per decision log §3).
func buildOrganizationSignupService(deps Deps, auditLog *audit.Logger, logger *zap.Logger) *service.OrganizationSignupService {
	if !deps.Config.IsMultiMode() {
		return nil
	}
	return service.NewOrganizationSignupService(
		deps.TenantAdmin,
		deps.RepositoryForTenant,
		deps.Config,
		deps.Signer,
		auditLog,
		logger,
	)
}

// buildDomainService returns the wired DomainService backing the tenant
// domain-verification RPCs, or nil when the governance stores are absent
// (entdb/memory have no control plane). The Connect handler treats nil as
// "disabled" and returns CodeUnimplemented. A nil DNS resolver lets
// NewDomainService default to net.DefaultResolver.
func buildDomainService(deps Deps, logger *zap.Logger) *service.DomainService {
	if deps.DomainStore == nil || deps.TenantStore == nil || deps.MembershipStore == nil {
		return nil
	}
	return service.NewDomainService(
		deps.DomainStore,
		deps.TenantStore,
		deps.MembershipStore,
		nil,
		deps.Config,
		logger,
	)
}

// wrapOAuthRegistry returns a registry whose Exchangers are wrapped
// with an OTel client-kind span for the outbound token-endpoint POST.
// The wrapped registry shares no state with the input — the input is
// expected to be the freshly-built per-process registry, not a
// shared one.
func wrapOAuthRegistry(in *oauth.Registry) *oauth.Registry {
	if in == nil {
		return in
	}
	out := oauth.NewRegistry()
	for _, name := range in.Providers() {
		e, ok := in.Get(name)
		if !ok {
			continue
		}
		out.Register(name, observability.WrapOAuthExchanger(name, e))
	}
	return out
}
