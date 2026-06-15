// Package identityserver is identity's embeddable public API. It lets a
// Go program import identity and mount it into an existing server
// instead of running the dedicated container.
//
// Two mount surfaces are exposed, both backed by one service-layer
// wiring:
//
//	srv, err := identityserver.New(ctx, identityserver.OptionsFromEnv())
//	mux.Handle("/", srv.Handler())   // Connect (gRPC, gRPC-Web, Connect)
//	srv.RegisterGRPC(grpcServer)     // native registration on a *grpc.Server
//	srv.Start(ctx)                   // background workers (audit, sweeper, signer reload)
//	defer srv.Shutdown(ctx)
//
// Handler returns the full middleware chain (CORS, auth, rate-limit,
// metrics, health, JWKS) wrapping the Connect handler — mount it on any
// HTTP/2 (or h2c) server. RegisterGRPC bridges identity's Connect
// service implementation onto a host *grpc.Server; the host owns the
// listener and any gRPC-side auth interceptors.
//
// cmd/identity is a thin shim over this package: it calls New with
// OptionsFromEnv and serves Handler, so the container behaves
// identically to embedding identity over HTTP.
package identityserver

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	entclient "github.com/elloloop/identity/internal/repo/entdb/entclient"
	"github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/observability"
	"github.com/elloloop/identity/internal/repo"
	"github.com/elloloop/identity/internal/service"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/passkeys"
)

// Server is a constructed, mountable identity service. Build it with
// New, expose it via Handler and/or RegisterGRPC, run its background
// workers with Start, and tear everything down with Shutdown.
type Server struct {
	built  *app.Built
	logger *zap.Logger

	// shutdownFns run in Shutdown, in reverse construction order, to
	// release everything New acquired (signer watcher, EntDB client,
	// OTel exporter). Each is wrapped to bound and log its own failure.
	shutdownFns []func(context.Context) error
}

// New assembles the identity service from opts. It builds the
// persistence, signer, WebAuthn, IDV and OpenTelemetry adapters that are
// not already injected, validates the configuration, and wires the
// service layer. It does NOT start background workers or bind any
// listener — call Start once you are ready to serve and Shutdown to
// drain.
//
// ctx scopes the construction-time setup (EntDB dial, AWS config load,
// OTel exporter init); it is not retained.
func New(ctx context.Context, opts Options) (*Server, error) {
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	cfg := opts.Config

	s := &Server{logger: logger}

	otelShutdown, err := observability.Setup(ctx, observability.FromAppConfig(&cfg))
	if err != nil {
		return nil, fmt.Errorf("otel setup: %w", err)
	}
	s.shutdownFns = append(s.shutdownFns, otelShutdown)

	// EntDB client. Built once and shared by the repository adapter. Only
	// needed when New itself builds the persistence layer against the entdb
	// driver; an injected Repo/DB pair or a non-entdb driver leaves it nil.
	var entdbClient *entdb.DbClient
	needsEntDBClient := opts.Repo == nil && opts.DB == nil &&
		repo.Driver(cfg.RepoDriver) == repo.DriverEntDB
	if needsEntDBClient {
		entdbClient, err = newEntDBClient(ctx, cfg.EntDBAddress)
		if err != nil {
			s.cleanupOnError(ctx)
			return nil, err
		}
		s.shutdownFns = append(s.shutdownFns, func(context.Context) error {
			return entdbClient.Close()
		})
	}

	signer := opts.Signer
	if signer == nil {
		var stopSigner func()
		signer, stopSigner, err = buildSigner(ctx, &cfg, logger)
		if err != nil {
			s.cleanupOnError(ctx)
			return nil, fmt.Errorf("jwt signer: %w", err)
		}
		s.shutdownFns = append(s.shutdownFns, func(context.Context) error {
			stopSigner()
			return nil
		})
	}
	if err := jwtpkg.AssertJWKSIncludesActiveKIDs(signer, time.Now().UTC()); err != nil {
		s.cleanupOnError(ctx)
		return nil, fmt.Errorf("jwks active kid drift: %w", err)
	}

	webauthnSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		s.cleanupOnError(ctx)
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	totpKey, err := decodeTOTPKey(&cfg, logger)
	if err != nil {
		s.cleanupOnError(ctx)
		return nil, err
	}
	totpRecoveryPepper, err := decodeTOTPRecoveryPepper(&cfg, logger)
	if err != nil {
		s.cleanupOnError(ctx)
		return nil, err
	}

	authRepo, dbAdapter := opts.Repo, opts.DB
	var projectResolver service.ProjectResolver
	var tenantAutoFormer service.TenantAutoFormStore
	var domainStore service.DomainStore
	var tenantStore service.TenantStore
	var membershipStore service.MembershipStore
	var invitationStore service.InvitationStore
	var controlPlaneStore service.ControlPlaneProjectStore
	var platformAdminStore service.PlatformAdminStore
	var loginGovernance *service.LoginGovernance
	if authRepo == nil || dbAdapter == nil {
		built, buildErr := repo.Build(ctx, repo.Config{
			Driver:      repo.Driver(cfg.RepoDriver),
			EntDBClient: entdbClient,
			// The boot-default Repository/DB binds to the default project
			// (ADR-0002): the Project is the storage shard, so the data-plane
			// partition is DefaultProjectID, NOT the DefaultTenantID storage
			// scope. ensureDefaultProject (below) seeds a Project row whose id
			// equals DefaultProjectID so rows written under this binding are
			// readable and the FK to projects(id) is satisfied.
			ProjectID:                 cfg.DefaultProjectID,
			PostgresDSN:               cfg.PostgresDSN,
			PostgresMaxConns:          cfg.PostgresMaxConns,
			PostgresAutoMigrate:       cfg.PostgresAutoMigrate,
			RequireVerifiedAuthDomain: cfg.RequireVerifiedAuthDomain,
		}, logger)
		if buildErr != nil {
			s.cleanupOnError(ctx)
			return nil, fmt.Errorf("repo build: %w", buildErr)
		}
		authRepo, dbAdapter = built.Repository, built.DB
		projectResolver = built.ProjectResolver()
		tenantAutoFormer = built.TenantAutoFormer()
		domainStore = built.DomainStoreIface()
		tenantStore = built.TenantStoreIface()
		membershipStore = built.MembershipStoreIface()
		invitationStore = built.InvitationStoreIface()
		controlPlaneStore = built.ControlPlaneStore()
		platformAdminStore = built.PlatformAdminStoreIface()
		loginGovernance = built.LoginGovernance()

		// Seed the control-plane default project (postgres only; entdb/
		// memory have no control plane, so built.ProjectStore is nil). The
		// project is the zero-config isolation entity later slices pin
		// requests to, and maps onto the DefaultTenantID storage scope. Its
		// table comes from migration 0013, so a postgres deployment must
		// have run `identity migrate` (or set GATEWAY_POSTGRES_AUTO_MIGRATE)
		// before first boot — surfaced fail-fast below rather than as a
		// confusing error on the first request.
		if err := ensureDefaultProject(ctx, built, &cfg, logger); err != nil {
			s.cleanupOnError(ctx)
			return nil, err
		}

		// Seed the default project's branded serving hostnames from config
		// (GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS) so the Host→project resolver
		// maps them to the default project. Deployer-owned, so seeded verified.
		if err := ensureProjectAuthDomains(ctx, built, &cfg, logger); err != nil {
			s.cleanupOnError(ctx)
			return nil, err
		}
	}

	idvProvider := opts.IDVProvider
	if idvProvider == nil {
		idvProvider, err = buildIDVProvider(&cfg, logger)
		if err != nil {
			s.cleanupOnError(ctx)
			return nil, fmt.Errorf("idv provider: %w", err)
		}
	}

	// app.New starts no goroutines; its background workers (sweeper, audit
	// flusher) own their root context, created and cancelled by
	// Start/Shutdown, not the construction ctx.
	built, err := app.New(app.Deps{ //nolint:contextcheck // workers own their context, not New's ctx
		Config:             &cfg,
		Logger:             logger,
		Signer:             signer,
		Repo:               authRepo,
		DB:                 dbAdapter,
		Passkeys:           webauthnSvc,
		TOTPKey:            totpKey,
		TOTPRecoveryPepper: totpRecoveryPepper,
		EmailTransport:     opts.EmailTransport,
		SMSSender:          opts.SMSSender,
		OAuthRegistry:      opts.OAuthRegistry,
		IDVProvider:        idvProvider,
		CaptchaVerifier:    opts.CaptchaVerifier,
		MetricsRegistry:    opts.MetricsRegistry,
		ProjectResolver:    projectResolver,
		TenantAutoFormer:   tenantAutoFormer,
		DomainStore:        domainStore,
		TenantStore:        tenantStore,
		MembershipStore:    membershipStore,
		InvitationStore:    invitationStore,
		ControlPlaneStore:  controlPlaneStore,
		PlatformAdminStore: platformAdminStore,
		LoginGovernance:    loginGovernance,
		DNSResolver:        opts.DNSResolver,
	})
	if err != nil {
		s.cleanupOnError(ctx)
		return nil, err
	}
	s.built = built
	return s, nil
}

// defaultProjectName is the human-readable name stamped on the
// auto-seeded default project.
const defaultProjectName = "Default Project"

// ensureDefaultProject idempotently seeds the control-plane default
// project when identity built a postgres-backed repository. It is a no-op
// for entdb/memory (built.ProjectStore is nil) and when
// DefaultProjectID is explicitly blank. The project's id is
// DefaultProjectID; it maps onto the DefaultTenantID storage scope. Any
// error fails boot (fail-fast) with a hint to run migrations, since a
// missing projects table means migration 0013 was never applied.
func ensureDefaultProject(ctx context.Context, built *repo.Built, cfg *Config, logger *zap.Logger) error {
	if built.ProjectStore == nil || cfg.DefaultProjectID == "" {
		return nil
	}
	proj, err := built.ProjectStore.EnsureDefaultProject(
		ctx, cfg.DefaultProjectID, cfg.DefaultTenantID, defaultProjectName,
	)
	if err != nil {
		return fmt.Errorf(
			"default project bootstrap (run `identity migrate` if the projects table is missing): %w",
			err,
		)
	}
	logger.Info("default_project_ensured",
		zap.String("project_id", proj.ID),
		zap.String("storage_scope_id", proj.StorageScopeID))
	return nil
}

// ensureProjectAuthDomains idempotently seeds the default project's branded
// serving hostnames from GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS — the first
// entry is the primary (drives branded link/cookie building), the rest are
// additional serving hosts. All are seeded VERIFIED: they are deployer-owned
// (a customer-supplied custom domain goes through DNS verification instead).
// A no-op when there is no control plane, no default project, or no domains
// configured. Any error fails boot, like the project bootstrap.
func ensureProjectAuthDomains(ctx context.Context, built *repo.Built, cfg *Config, logger *zap.Logger) error {
	if built.ProjectStore == nil || cfg.DefaultProjectID == "" {
		return nil
	}
	hosts := cfg.DefaultProjectAuthDomainList()
	if len(hosts) == 0 {
		return nil
	}
	verifiedAt := time.Now().UnixMilli()
	for i, host := range hosts {
		isPrimary := i == 0
		if err := built.ProjectStore.EnsureAuthDomain(ctx, cfg.DefaultProjectID, host, isPrimary, verifiedAt); err != nil {
			return fmt.Errorf("seed auth domain %q: %w", host, err)
		}
		logger.Info("project_auth_domain_seeded",
			zap.String("project_id", cfg.DefaultProjectID),
			zap.String("hostname", host),
			zap.Bool("primary", isPrimary))
	}
	return nil
}

// Handler returns the identity HTTP handler: the full middleware chain
// wrapping the Connect-RPC mux. It serves the Connect, gRPC, and
// gRPC-Web protocols, plus /health, /readyz and /.well-known/jwks.json.
// Mount it on any HTTP/2 (or h2c) server.
func (s *Server) Handler() http.Handler {
	return s.built.Handler
}

// RegisterGRPC registers identity onto an existing *grpc.Server (any
// grpc.ServiceRegistrar). The host owns the listener and any gRPC-side
// interceptors. The registered service delegates to the same Connect
// service implementation Handler serves, so both surfaces share one
// wiring.
//
// Note: the HTTP middleware chain (CORS, rate-limit, the JWT auth
// middleware that populates X-Authenticated-User-Id, health, JWKS) is
// HTTP-only. Over native gRPC the host is responsible for authentication
// — supply a server interceptor that verifies the bearer token and
// forwards identity's expected metadata (see docs/embedding.md).
func (s *Server) RegisterGRPC(reg grpc.ServiceRegistrar) {
	identitypb.RegisterIdentityServiceServer(reg, newGRPCBridge(s.built.ConnectHandler))
}

// Start launches the background workers: the async audit flusher, the
// expired-row sweeper, and (for the file signer) SIGHUP-driven key
// reload. It is idempotent. ctx is accepted for symmetry and future use;
// the workers manage their own lifetimes and stop on Shutdown.
func (s *Server) Start(_ context.Context) error {
	s.built.Start()
	return nil
}

// Shutdown drains the background workers and releases every resource New
// acquired (signer watcher, EntDB client, OTel exporter), in reverse
// order. It is safe to call without a preceding Start and safe to call
// more than once. The first non-nil release error is returned after all
// releases run.
func (s *Server) Shutdown(ctx context.Context) error {
	s.built.Stop()
	return s.runShutdownFns(ctx)
}

// cleanupOnError releases whatever New already acquired when a later
// construction step fails, so a failed New leaks nothing.
func (s *Server) cleanupOnError(ctx context.Context) {
	_ = s.runShutdownFns(ctx)
}

func (s *Server) runShutdownFns(ctx context.Context) error {
	var firstErr error
	for i := len(s.shutdownFns) - 1; i >= 0; i-- {
		if err := s.shutdownFns[i](ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.shutdownFns = nil
	return firstErr
}

// newEntDBClient dials the EntDB server. The dial is lazy in the SDK, so
// Connect returning nil does not guarantee reachability; it surfaces
// configuration errors (bad address format) early.
func newEntDBClient(ctx context.Context, address string) (*entdb.DbClient, error) {
	db, err := entclient.New(address)
	if err != nil {
		return nil, fmt.Errorf("entdb client: %w", err)
	}
	if err := db.Connect(ctx); err != nil {
		return nil, fmt.Errorf("entdb connect: %w", err)
	}
	return db, nil
}
