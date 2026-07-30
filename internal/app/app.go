// Package app builds the identity service HTTP handler from injected
// dependencies. It is shared by the production binary (cmd/identity)
// and the integration test harness (tests/integration), so that both
// exercise the exact same wiring code: middleware chain, audit logger,
// service layer, and Connect-RPC handler registration.
package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/app/ui"
	"github.com/elloloop/identity/internal/config"
	identityconnect "github.com/elloloop/identity/internal/connect"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/observability"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/events"
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

	// ProjectSecretsKey is the 32-byte AES-256 key that decrypts per-project
	// secrets at rest (hosted-flow OAuth provider secrets in a project's
	// config_json). Empty/nil on drivers without a control plane, where every
	// request pins to the default project (env OAuth providers). Decoded from
	// GATEWAY_PROJECT_SECRETS_KEY by the composition root.
	ProjectSecretsKey []byte

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

	// InvitationStore backs the tenant-invitation RPCs
	// (CreateTenantInvitation / AcceptTenantInvitation /
	// ListTenantInvitations). Non-nil ONLY for the postgres driver; when nil
	// (together with the membership/tenant stores) the MembershipService is
	// not constructed and the membership RPCs return Unimplemented.
	InvitationStore service.InvitationStore

	// ControlPlaneStore is the project write-store backing the control-plane
	// admin RPCs (AdminCreateProject and friends). Non-nil ONLY for the
	// postgres driver; when nil (together with the tenant/membership stores)
	// the ControlPlaneAdminService is not constructed and the admin RPCs
	// return Unimplemented. Even when wired, the surface stays disabled until
	// Config.AdminAPISecret is set.
	ControlPlaneStore service.ControlPlaneProjectStore

	// NativeOAuthProjects is the control-plane project-by-id lookup
	// NativeOAuthLogin uses to validate a product→project id. Non-nil ONLY for
	// the postgres driver; nil on drivers without a control plane, where native
	// login accepts only the product that resolves to the default project.
	NativeOAuthProjects service.NativeOAuthProjectStore

	// PlatformAdminStore backs the trust-on-first-use first-admin bootstrap
	// (CreateFirstPlatformAdmin). Non-nil ONLY for the postgres driver; when
	// nil the bootstrap RPC returns Unimplemented. The bootstrap stays
	// zero-config only when no admin secret is set: when Config.AdminAPISecret
	// is configured it is secret-gated like the other admin RPCs, and
	// Config.DisableFirstAdminBootstrap closes it entirely. It self-secures by
	// closing once any admin exists.
	PlatformAdminStore service.PlatformAdminStore

	// LoginPolicyStore backs the operator LoginPolicy-authoring admin RPCs
	// (UpsertLoginPolicy / GetLoginPolicy / DeleteLoginPolicy) — the write
	// side of the policy the login path enforces. Non-nil ONLY for the
	// postgres driver; when nil those RPCs return Unimplemented.
	LoginPolicyStore service.LoginPolicyStore

	// LoginGovernance is the read-side bundle the login path consults to
	// enforce a claimed tenant's LoginPolicy. Non-nil only for the postgres
	// driver (the only one with a governance plane); when nil, login imposes
	// no policy restriction.
	LoginGovernance *service.LoginGovernance

	// DNSResolver is the TXT-lookup boundary VerifyDomain uses to confirm a
	// domain's ownership challenge. nil defaults to net.DefaultResolver
	// (production). The embedding API threads a custom resolver through here
	// so a full-stack test can publish the deterministic challenge without
	// touching real DNS.
	DNSResolver service.DNSResolver

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

	// NativeOAuthVerifier verifies native mobile-SDK ID tokens for
	// NativeOAuthLogin. May be nil — in that case New builds one from config
	// via buildNativeOAuthVerifier (which returns nil, leaving the RPC
	// disabled, unless GATEWAY_NATIVE_OAUTH_ENABLED and audiences are set).
	// Tests inject a verifier pointed at a mock JWKS through this override,
	// mirroring OAuthRegistry.
	NativeOAuthVerifier *oauth.NativeVerifier

	// IDVProvider drives identity-verification (document + selfie).
	// May be nil — in that case BeginIdentityVerification returns
	// CodeUnimplemented. Production deployments wire an Azure or
	// other real provider; tests typically pass an idv.StubProvider.
	IDVProvider idv.Provider

	// CaptchaVerifier gates the unauthenticated auth endpoints. May be
	// nil — in that case New builds one from Config (the no-op verifier
	// when CAPTCHA is disabled). Tests inject a fake to drive pass/fail
	// without network calls.
	CaptchaVerifier assurance.Verifier

	// MetricsRegistry is the Prometheus registry the server records
	// RED metrics into. May be nil — in that case the default
	// registry is used (which is what production wants). Tests pass an
	// isolated registry so they can read counters without colliding
	// with other tests in the same process.
	MetricsRegistry prometheus.Registerer

	// SynchronousEmailSend forces request-phase credential-email sends to run
	// inline instead of on a detached goroutine. Production leaves it false, so
	// New enables asynchronous dispatch (decoupling SMTP latency from RPC
	// response time — the send timing oracle). Full-stack tests that read the
	// recording mailer right after a request set it true for deterministic
	// observation without polling.
	SynchronousEmailSend bool
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
			PathPrefix: "/identity.v1.IdentityService/PasswordSignup", Tag: "signup",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitSignupPerIP, 0),
		},
		{
			PathPrefix: "/identity.v1.IdentityService/PasswordLogin", Tag: "login",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitLoginPerIP, 0),
		},
		{
			PathPrefix: "/identity.v1.IdentityService/RequestPasswordReset", Tag: "reset",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitResetPerIP, 0),
		},
		{
			PathPrefix: "/identity.v1.IdentityService/SendEmailVerification", Tag: "verify",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitVerifyPerIP, 0),
		},
		{
			// Passwordless OTP request: unauthenticated, sends an email.
			// Tight per-IP quota so a single source can't pump codes at a
			// victim inbox (the per-email cooldown is the second layer).
			PathPrefix: "/identity.v1.IdentityService/RequestEmailLoginCode", Tag: "passwordless_code",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitPasswordlessPerIP, 0),
		},
		{
			// Passwordless magic-link request: same shape, same quota.
			PathPrefix: "/identity.v1.IdentityService/RequestMagicLink", Tag: "passwordless_link",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitPasswordlessPerIP, 0),
		},
		{
			// Phone-verification OTP request: authenticated, but each call
			// sends an SMS, so a tight per-IP quota bounds cost/abuse (the
			// per-user cooldown is the second layer).
			PathPrefix: "/identity.v1.IdentityService/RequestPhoneVerification", Tag: "phone_verify",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitPhonePerIP, 0),
		},
		{
			PathPrefix: "/identity.v1.IdentityService/BeginOAuthLogin", Tag: "oauth_begin",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitLoginPerIP, 0),
		},
		{
			// Native mobile sign-in (Google/Apple ID-token verification) is a
			// login surface, bound by the same per-IP login quota as OAuthLogin.
			PathPrefix: "/identity.v1.IdentityService/NativeOAuthLogin", Tag: "native_oauth",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitLoginPerIP, 0),
		},
		{
			PathPrefix: "/identity.v1.IdentityService/BeginPasskeyLogin", Tag: "passkey_begin",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitLoginPerIP, 0),
		},
		{
			// Passkey-first signup: unauthenticated account creation. Bound by
			// the same per-IP signup quota as PasswordSignup so it cannot be
			// used to mass-create accounts or pump verification mail.
			PathPrefix: "/identity.v1.IdentityService/BeginPasskeySignup", Tag: "passkey_signup",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitSignupPerIP, 0),
		},
		{
			PathPrefix: "/identity.v1.IdentityService/VerifyTotp", Tag: "totp_verify",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitLoginPerIP, 0),
		},
		{
			// First-admin bootstrap: the one unauthenticated, NON-secret-gated
			// admin RPC. It self-closes once any platform admin exists, but
			// while open (a fresh deployment) it must not be hammerable — a
			// tight per-IP quota bounds brute-force / probe traffic against the
			// ungated endpoint.
			PathPrefix: "/identity.v1.IdentityService/CreateFirstPlatformAdmin", Tag: "first_admin_bootstrap",
			Limiter: middleware.NewFixedWindowLimiter(window, cfg.RateLimitBootstrapPerIP, 0),
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

	// Normalize an empty DefaultProjectID to a non-empty default. The env
	// loader (config.Load) already defaults GATEWAY_DEFAULT_PROJECT_ID, but
	// struct-literal Configs — every test harness and every embedding caller
	// that builds Config directly — bypass that. This value becomes the
	// boot-default project shard id for the audit logger and every service
	// below (and, via requestProjectID, the graph partition key / postgres
	// WHERE project_id), so it must never be "": the graph transport rejects an empty
	// partition key outright, and a data-plane row written under "" has no
	// valid project. Default it rather than reject it, mirroring how the
	// env loader defaults DefaultTenantID, so embedding ergonomics hold.
	if deps.Config.DefaultProjectID == "" {
		deps.Config.DefaultProjectID = config.DefaultProjectIDFallback
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

	// The audit logger is a boot-scoped singleton, but each write is scoped to
	// the request's project at Log time via the injected ProjectScoper: it
	// resolves the project from the request's ProjectScope (falling back to the
	// boot default) and binds the writer to that project's storage partition
	// (ADR-0002 — the Project is the data-plane shard). This keeps audit writes
	// under the SAME project ProfileService.ListAuditEvents reads from, so
	// events round-trip in a multi-project deployment. deps.DB is captured by
	// the closure so the scoper rebinds the live boot DB per request.
	bootDB := deps.DB
	defaultProjectID := deps.Config.DefaultProjectID
	auditLog := audit.NewLogger(bootDB, defaultProjectID, logger).
		WithProjectScoper(func(ctx context.Context) (audit.NodeWriter, string) {
			scopedDB, projectID := service.ScopedDB(ctx, bootDB, defaultProjectID)
			if scopedDB == nil {
				// Preserve audit.Logger's nil-writer contract: hand back a
				// typed nil so the logger's nil check fires, rather than a
				// non-nil interface wrapping a nil *DB.
				return nil, projectID
			}
			return scopedDB, projectID
		})

	// Garbage-collection sweeper for expired ephemeral rows (#94) plus the
	// self-service account-deletion purge and the audit-log retention sweep
	// (GDPR Art 5(1)(e)). Disabled when SweeperIntervalSeconds <= 0 — deployers
	// who already run their own GC, and the unit-test harness, both flip it off
	// via GATEWAY_SWEEPER_INTERVAL_SECONDS=0. Constructed below once adminSvc
	// (the account purger) exists.
	var sweep *sweeper

	// Background-worker lifecycle. The audit flusher and sweeper do NOT
	// start in New — they start when the consumer calls (*Built).Start,
	// so an embedding host controls when goroutines run, and drain when
	// it calls (*Built).Stop. Until Start runs, audit writes happen
	// synchronously on the calling goroutine (audit.Logger falls back to
	// sync mode), so a never-started Built is still correct, just slower.
	var stopAudit, stopSweeper func()
	// Event-worker lifecycle hooks; populated below only when outbound
	// eventing is enabled (else they stay nil and the worker never runs).
	var startEvents, stopEvents func()
	startWork := func() {
		// Move audit writes off the auth hot path. Drops are counted and
		// surfaced via auditLog.DroppedCount().
		stopAudit = auditLog.StartAsync(deps.Config.AuditQueueSize)
		if sweep != nil {
			stopSweeper = sweep.start()
		}
		if startEvents != nil {
			startEvents()
		}
	}
	stopWork := func() {
		if stopEvents != nil {
			stopEvents()
		}
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

	// Resolve the native-OAuth verifier into the service-layer seam. Assign
	// only a non-nil concrete verifier so the interface stays a true nil when
	// native login is disabled — boxing a typed-nil *oauth.NativeVerifier would
	// make WithNativeOAuth's "nil disables the RPC" guard read non-nil.
	var nativeVerifier service.NativeIDTokenVerifier
	if v := deps.NativeOAuthVerifier; v != nil {
		nativeVerifier = v
	} else if v := buildNativeOAuthVerifier(deps.Config, logger); v != nil {
		nativeVerifier = v
	}

	// User-lifecycle eventing (#261): webhooks disabled yields a nil publisher
	// (the service treats nil as the no-op path) and nil lifecycle hooks; enabled,
	// an outbox-backed publisher plus a background worker deliver signed webhooks.
	// Extracted to buildEventing so New's wiring stays flat.
	eventPublisher, startEvents, stopEvents, err := buildEventing(deps, logger)
	if err != nil {
		return nil, err
	}

	authSvc := service.NewAuthServiceWithOAuth(
		repo, deps.Config, deps.Signer, deps.Passkeys,
		auditLog, deps.TOTPKey, deps.TOTPRecoveryPepper, mailer, smsSender, logger,
		oauthRegistry,
	).WithTenantAutoFormer(deps.TenantAutoFormer).
		WithLoginGovernance(deps.LoginGovernance).
		WithEventPublisher(eventPublisher).
		WithNativeOAuth(nativeVerifier, deps.NativeOAuthProjects).
		WithProjectOAuthSecrets(deps.ProjectSecretsKey, observability.WrapOAuthExchanger)
	// Dispatch credential emails asynchronously in the served deployment so SMTP
	// latency cannot time the gated send/no-send decision. Tests that read the
	// mailer synchronously opt out via Deps.SynchronousEmailSend.
	if !deps.SynchronousEmailSend {
		authSvc = authSvc.WithAsyncEmailDispatch()
	}
	adminSvc := service.NewAdminService(repo, deps.DB, deps.Config.DefaultProjectID, auditLog, deps.Config, mailer, logger).
		WithEventPublisher(eventPublisher)

	// Now that the account purger (adminSvc) exists, build the sweeper. It runs
	// the ephemeral-row GC AND the account-deletion purge on the same tick.
	sweep = newSweeper(
		deps.Repo,
		adminSvc,
		deps.Config.SweeperIntervalSeconds,
		deps.Config.SweeperBatchSize,
		deps.Config.SweeperGraceSeconds,
		deps.Config.AuditRetentionDays,
		logger,
	)
	groupsSvc := service.NewGroupService(deps.DB, deps.Config.DefaultProjectID, auditLog, logger)
	helpSvc := service.NewHelpService(deps.DB, deps.Config.DefaultProjectID, auditLog, logger)
	// COPPA data-minimization: one minimizer derived from the age gate +
	// GATEWAY_MINOR_DATA_MINIMIZATION, shared by the profile and IDV services
	// so the "is this a minimized child?" rule lives in one place. A no-op
	// when either toggle is off.
	minorData := service.NewMinorDataMinimizer(
		deps.Config.MinorDataMinimization,
		service.BuildAgeGate(deps.Config, logger),
		nil,
	)

	profileSvc := service.NewProfileService(repo, deps.DB, deps.Config.DefaultProjectID, auditLog, logger).
		WithMinorDataMinimizer(minorData).
		WithLoginGovernance(deps.LoginGovernance).
		WithAccountDeletionGraceDays(deps.Config.AccountDeletionGraceDays).
		WithExportMaxAuditEvents(deps.Config.ExportMaxAuditEvents)

	var idvSvc *service.IdentityVerificationService
	if deps.IDVProvider != nil {
		idvSvc = service.NewIdentityVerificationService(
			repo, observability.WrapIDVProvider(deps.IDVProvider), deps.Config.DefaultProjectID, logger,
		).WithMinorDataMinimizer(minorData)
	}

	captchaVerifier := deps.CaptchaVerifier
	if captchaVerifier == nil {
		captchaVerifier, err = buildCaptchaVerifier(deps.Config, logger)
		if err != nil {
			return nil, fmt.Errorf("captcha verifier: %w", err)
		}
	}

	domainSvc := buildDomainService(deps, logger)
	membershipSvc := buildMembershipService(deps, repo, mailer, logger)
	controlAdminSvc := buildControlPlaneAdminService(deps, auditLog, logger)
	handler := identityconnect.NewIdentityHandler(authSvc, adminSvc, groupsSvc, helpSvc, profileSvc, idvSvc, domainSvc, membershipSvc, controlAdminSvc, captchaVerifier, deps.Config)

	connectOpts, err := buildConnectHandlerOptions(deps.Config)
	if err != nil {
		return nil, fmt.Errorf("otelconnect interceptor: %w", err)
	}

	mux := http.NewServeMux()
	path, svcHandler := identityconnectgen.NewIdentityServiceHandler(handler, connectOpts...)
	mux.Handle(path, svcHandler)

	// Browser-facing hosted OAuth routes (#126). Registered only when
	// GATEWAY_OAUTH_ALLOWED_RETURN_URLS is non-empty; the headless
	// BeginOAuthLogin / OAuthLogin RPCs work regardless.
	returnAllow := service.ParseReturnAllowlist(deps.Config.OAuthAllowedReturnURLs)

	// Default auth UI (login/signup). Rendered per request so it offers
	// exactly the sign-in options the resolved project enables server-side.
	mux.Handle("/auth/", ui.Handler(deps.Config, authSvc, returnAllow.Enabled()))
	if returnAllow.Enabled() {
		logger.Info("oauth_hosted_flow_enabled", zap.Strings("allowed_return_urls", returnAllow.Entries()))
	} else {
		logger.Info("oauth_hosted_flow_disabled",
			zap.String("hint", "set GATEWAY_OAUTH_ALLOWED_RETURN_URLS to enable GET /oauth/start + /oauth/callback"))
	}
	(&hostedOAuthHandler{auth: authSvc, allowlist: returnAllow, logger: logger}).register(mux)

	// Inbound SCIM 2.0 provisioning (#260). Registered only when
	// GATEWAY_SCIM_ENABLED is true (and Validate has confirmed a bearer token
	// + project id); otherwise /scim/v2/* 404s and the headless RPCs are
	// unaffected. Every SCIM operation is scoped to the single configured
	// project, so the deployment-wide bearer token can only touch that
	// project's users.
	if deps.Config.SCIMEnabled {
		// Fail fast on a typo'd GATEWAY_SCIM_PROJECT_ID: verify at boot that it
		// names a real, ACTIVE project rather than 500-ing on the first request.
		// Only the postgres driver has a control plane to check against (the
		// lookup is nil for memory, which pins all data to the default project).
		if err := validateSCIMProject(deps.NativeOAuthProjects, deps.Config.SCIMProjectID); err != nil {
			return nil, err
		}
		logger.Info("scim_server_enabled",
			zap.String("mount", "/scim/v2/"),
			zap.String("project_id", deps.Config.SCIMProjectID))
		(&scimHandler{
			repo:        repo,
			projectID:   deps.Config.SCIMProjectID,
			bearerToken: deps.Config.SCIMBearerToken,
			audit:       auditLog,
			publisher:   eventPublisher,
			tenantID:    deps.Config.DefaultTenantID,
			logger:      logger,
		}).register(mux, true)
	} else {
		logger.Info("scim_server_disabled",
			zap.String("hint", "set GATEWAY_SCIM_ENABLED=true, GATEWAY_SCIM_BEARER_TOKEN and GATEWAY_SCIM_PROJECT_ID to enable /scim/v2"))
	}

	// SAML 2.0 IdP surface (#255). Mounted only when GATEWAY_SAML_IDP_ENABLED
	// is set with valid signing material; a disabled deployment registers no
	// routes, so /saml/* returns 404 (unchanged behavior).
	samlIssuer, err := buildSAMLIssuer(deps.Config, logger)
	if err != nil {
		return nil, fmt.Errorf("saml issuer: %w", err)
	}
	(&samlHandler{issuer: samlIssuer, logger: logger}).register(mux)

	rpcMetrics, err := middleware.NewRPCMetrics(deps.MetricsRegistry)
	if err != nil {
		return nil, fmt.Errorf("rpc metrics: %w", err)
	}

	// Every token's "tenant" claim must equal the internal storage tenant
	// key (DefaultTenantID), so the auth middleware pins it.
	authExpectedTenant := deps.Config.DefaultTenantID

	// Order (outermost runs first on request path):
	//   logging → recover → health → project → CORS → product → client-IP → rate-limit → JWKS → auth → project-guard → metrics → Connect
	// client-IP must precede rate-limit (the limiter keys on the resolved
	// IP). health is the outermost functional hop so liveness/readiness
	// probes short-circuit before any per-request work — including the
	// project resolver's Host lookup, which must not run on probe traffic.
	// The project resolver runs just OUTSIDE CORS (and thus outside auth,
	// rate-limit and the rest) so the resolved project is in context for the
	// CORS middleware — including the unauthenticated OPTIONS preflight,
	// which carries no credential key and so resolves by Host. CORS layers
	// the resolved project's per-project allow-list on top of the global
	// floor and short-circuits the preflight before rate-limit, so a
	// preflight is never rate-limited. The resolver still precedes auth and
	// the service layer, and pins the default project when no control-plane
	// resolver is wired. product resolution sits just INSIDE CORS, so it is
	// skipped for a short-circuited preflight but stamps every real request —
	// including the ones the rate limiter or auth will reject — with the
	// X-Product slug the session-issuing paths gate on. metrics sits just
	// outside the Connect mux so it observes every RPC's final status,
	// including any failure synthesized by the otelconnect interceptor.
	var chain http.Handler = mux
	chain = middleware.MetricsMiddleware(rpcMetrics)(chain)
	// Project-scope guard runs just after auth (which surfaces the verified
	// project), rejecting an access token replayed across projects.
	chain = middleware.NewProjectScopeGuard()(chain)
	chain = middleware.SessionAuthMiddleware(
		deps.Signer, authExpectedTenant, deps.Config.JWTAudience,
		deps.Config.JWTRequireAudience, sessionCache,
	)(chain)
	chain = middleware.JWKSMiddleware(deps.Signer)(chain)
	chain = middleware.RateLimitMiddleware(rateLimits, logger)(chain)
	chain = middleware.ClientIPMiddleware(trustedProxies)(chain)
	chain = middleware.NewProductResolver(deps.Config.DefaultProduct)(chain)
	chain = middleware.CORSMiddleware(allowedOrigins)(chain)
	// Build the env-configured default project's access policy once, failing the
	// boot loudly if the operator supplied an invalid mode/allowlist. The
	// resolver stamps it onto the default-project pin so the access guard is
	// deny-by-default until GATEWAY_DEFAULT_PROJECT_ACCESS_MODE opens it.
	defaultAccess, err := service.NewProjectAccessConfig(
		deps.Config.DefaultProjectAccessMode,
		deps.Config.DefaultProjectAllowedEmailList(),
		deps.Config.DefaultProjectAllowedDomainList(),
	)
	if err != nil {
		return nil, fmt.Errorf("default project access config: %w", err)
	}
	// Default-DENY is safe but easy to trip into unknowingly: warn loudly when the
	// default project denies all auth, so a fresh deployment that forgot to open
	// it isn't silently locked out with no signal.
	if defaultAccess.Mode == service.AccessModeClosed || defaultAccess.Mode == "" {
		logger.Warn("default_project_access_closed",
			zap.String("hint", "default project denies all authentication; set GATEWAY_DEFAULT_PROJECT_ACCESS_MODE=open (or allowlist/invite) to admit users"))
	}
	chain = middleware.NewProjectResolver(
		deps.Config.DefaultProjectID, deps.Config.DefaultTenantID,
		deps.Config.DefaultPrimaryAuthDomain(), defaultAccess,
		service.NewCachingProjectResolver(
			deps.ProjectResolver,
			deps.Config.ProjectResolutionCacheTTL(),
			deps.Config.ProjectResolutionCacheMaxEntries,
		),
		logger,
	)(chain)
	chain = middleware.HealthMiddleware(newDBReadinessProbe(deps.DB), chain)
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

// buildEventing wires user-lifecycle eventing (#261). Webhooks disabled returns
// a nil publisher — the service treats nil as the no-op events.Discard — and nil
// start/stop hooks so no worker runs. Enabled, it returns an outbox-backed
// publisher plus start/stop hooks that gate a background webhook worker
// (retry/backoff), so the embedding host controls when its goroutine runs. The
// in-memory outbox backs the single-node tier; a durable SQL outbox is a follow-up.
func buildEventing(deps Deps, logger *zap.Logger) (events.Publisher, func(), func(), error) {
	if !deps.Config.WebhooksEnabled {
		return nil, nil, nil, nil
	}
	outbox := events.NewMemoryOutbox()
	// Config.Validate (in New) already parsed these; the error is threaded only
	// so an out-of-band Config still fails boot loudly rather than silently
	// running with an empty outbox.
	subscriptions, err := deps.Config.WebhookSubscriptionList()
	if err != nil {
		return nil, nil, nil, err
	}
	seedWebhookSubscriptions(outbox, subscriptions, deps.Config.DefaultProjectID, logger)
	pub := events.NewOutboxPublisher(outbox, randomEventID, time.Now, logger)
	worker := events.NewWorker(events.WorkerConfig{
		Store:  outbox,
		Sender: events.NewHTTPSender(nil),
		Policy: events.RetryPolicy{
			MaxAttempts: deps.Config.WebhooksMaxAttempts,
			BaseDelay:   time.Duration(deps.Config.WebhooksBackoffBaseSeconds) * time.Second,
			MaxDelay:    time.Duration(deps.Config.WebhooksBackoffMaxSeconds) * time.Second,
		},
		Interval:    time.Duration(deps.Config.WebhooksWorkerIntervalSeconds) * time.Second,
		Batch:       deps.Config.WebhooksBatchSize,
		Logger:      logger,
		FailureHook: newWebhookFailureHook(logger),
	})
	ctx, cancel := context.WithCancel(context.Background())
	start := func() {
		go func() {
			if err := worker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("events_worker_stopped", zap.Error(err))
			}
		}()
	}
	return pub, start, cancel, nil
}

// buildDomainService returns the wired DomainService backing the tenant
// domain-verification RPCs, or nil when the governance stores are absent
// (the memory driver has no control plane). The Connect handler treats nil as
// "disabled" and returns CodeUnimplemented. A nil deps.DNSResolver lets
// NewDomainService default to net.DefaultResolver.
func buildDomainService(deps Deps, logger *zap.Logger) *service.DomainService {
	if deps.DomainStore == nil || deps.TenantStore == nil || deps.MembershipStore == nil {
		return nil
	}
	return service.NewDomainService(
		deps.DomainStore,
		deps.TenantStore,
		deps.MembershipStore,
		deps.DNSResolver,
		deps.Config,
		logger,
	)
}

// buildMembershipService returns the wired MembershipService backing the
// tenant invitation/membership RPCs, or nil when the governance stores are
// absent (the memory driver has no control plane). The Connect handler treats nil
// as "disabled" and returns CodeUnimplemented.
//
// mailerConfigured tells the service whether outbound mail actually delivers
// (a real transport is wired, not just the log-only fallback). When it does
// not, CreateTenantInvitation returns the raw token in its response so a
// headless deployment can still complete the flow. users is the boot-time
// repository — the redesign governance plane is a single postgres control
// database, so there is no per-tenant repo to scope user lookups to.
func buildMembershipService(deps Deps, users service.UserDirectory, mailer email.Transport, logger *zap.Logger) *service.MembershipService {
	if deps.InvitationStore == nil || deps.MembershipStore == nil || deps.TenantStore == nil {
		return nil
	}
	return service.NewMembershipService(
		deps.InvitationStore,
		deps.MembershipStore,
		deps.TenantStore,
		users,
		mailer,
		mailDeliveryConfigured(deps),
		deps.Config,
		logger,
	)
}

// buildControlPlaneAdminService returns the wired ControlPlaneAdminService
// backing the platform-operator admin RPCs, or nil when the control-plane
// stores are absent (the memory driver has no control plane). The Connect handler
// treats nil as "disabled" and returns CodeUnimplemented.
//
// The service is constructed even when no admin secret is configured: in that
// case it is constructed-but-disabled and every admin RPC returns
// Unimplemented (the secret check short-circuits on an empty secret). This
// keeps the "off by default" guarantee in one place — the service's
// constant-time authorize — rather than splitting it across the wiring.
func buildControlPlaneAdminService(deps Deps, auditLog *audit.Logger, logger *zap.Logger) *service.ControlPlaneAdminService {
	if deps.ControlPlaneStore == nil || deps.TenantStore == nil || deps.MembershipStore == nil {
		return nil
	}
	secret := ""
	disableBootstrap := false
	if deps.Config != nil {
		secret = deps.Config.AdminAPISecret
		disableBootstrap = deps.Config.DisableFirstAdminBootstrap
	}
	return service.NewControlPlaneAdminService(
		secret,
		disableBootstrap,
		deps.ProjectSecretsKey,
		deps.ControlPlaneStore,
		deps.TenantStore,
		deps.MembershipStore,
		deps.LoginPolicyStore,
		deps.PlatformAdminStore,
		deps.DNSResolver,
		auditLog,
		logger,
	)
}

// mailDeliveryConfigured reports whether outbound mail actually delivers, as
// opposed to the log-only fallback buildEmailTransport returns when nothing is
// configured. It is true when either:
//   - a custom EmailTransport was injected (a host or test wiring a real
//     transport — the only reason to inject one is to deliver), or
//   - the config wires a real SMTP provider (single host or the JSON chain),
//     mirroring buildEmailTransport's provider selection.
//
// When false, CreateTenantInvitation surfaces the raw token in its response so
// a deployment with no delivery channel can still hand it over out-of-band.
func mailDeliveryConfigured(deps Deps) bool {
	if deps.EmailTransport != nil {
		return true
	}
	cfg := deps.Config
	if cfg == nil {
		return false
	}
	return cfg.SMTPHost != "" || cfg.SMTPProviders != ""
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

// seedWebhookSubscriptions registers each configured subscription in the
// outbox so ListActiveSubscriptions returns them for the project the events
// are emitted under. A subscription with no explicit project is scoped to
// defaultProjectID — the project single-project deployments emit
// user-lifecycle events under. When no subscriptions are configured it logs a
// warning: webhooks are enabled but nothing will be delivered.
//
// The subscription secret is sensitive, so only the URL, resolved project,
// and event-type filter are logged — never the secret.
func seedWebhookSubscriptions(
	outbox *events.MemoryOutbox,
	subscriptions []config.WebhookSubscription,
	defaultProjectID string,
	logger *zap.Logger,
) {
	if len(subscriptions) == 0 {
		logger.Warn(
			"webhooks_enabled_without_subscriptions",
			zap.String("hint",
				"GATEWAY_WEBHOOKS_ENABLED=true but GATEWAY_WEBHOOK_SUBSCRIPTIONS is empty; "+
					"no events will be delivered"),
		)
		return
	}
	for _, sub := range subscriptions {
		projectID := sub.ProjectID
		if projectID == "" {
			projectID = defaultProjectID
		}
		outbox.AddSubscription(events.Subscription{
			ID:         webhookSubscriptionID(projectID, sub.URL),
			ProjectID:  projectID,
			URL:        sub.URL,
			Secret:     sub.Secret,
			EventTypes: sub.EventTypes,
			Active:     true,
		})
		logger.Info(
			"webhook_subscription_seeded",
			zap.String("url", sub.URL),
			zap.String("project_id", projectID),
			zap.Strings("event_types", eventTypeStrings(sub.EventTypes)),
		)
	}
}

// webhookSubscriptionID derives a stable subscription id from its project and
// URL. Stable (not random) so an operator can trace a delivery back to a
// config entry and so two identical entries collapse to one rather than
// double-delivering. The secret is deliberately excluded from the id.
func webhookSubscriptionID(projectID, url string) string {
	sum := sha256.Sum256([]byte(projectID + "\n" + url))
	return "whsub_" + hex.EncodeToString(sum[:8])
}

// eventTypeStrings renders an event-type filter for structured logging. An
// empty filter (matches all types) renders as an empty slice.
func eventTypeStrings(types []events.EventType) []string {
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = string(t)
	}
	return out
}

// newWebhookFailureHook returns the hook the events worker invokes when a
// delivery is abandoned after exhausting its retry budget. It surfaces the
// abandonment via the structured logger rather than swallowing it
// (acceptance criterion: failures surfaced, not hidden). Audit-event
// surfacing is a follow-up once the outbox is durable and per-tenant.
func newWebhookFailureHook(logger *zap.Logger) events.FailureHook {
	return func(d *events.Delivery) {
		logger.Error(
			"webhook_delivery_abandoned",
			zap.String("event_id", d.EventID),
			zap.String("subscription_id", d.SubscriptionID),
			zap.Int("attempts", d.Attempts),
			zap.String("last_error", d.LastError),
		)
	}
}

// randomEventID generates a unique outbox/event id for at-least-once
// delivery idempotency. crypto/rand failure is unrecoverable, so it panics
// rather than returning a guessable or empty id.
func randomEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("app: crypto/rand failed generating event id: " + err.Error())
	}
	return "evt_" + hex.EncodeToString(b[:])
}
