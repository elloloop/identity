package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
)

// Prometheus metrics for the sweeper. Counters are namespaced under
// "identity_" to match the existing convention; the node_type label
// value is one of the sweeper-target node types (see targets) so
// operators can scope alerts to "email_verification_tokens piling up"
// without matching the whole sweep.
//
// tenant-shard-db v1.14.0's OpDeleteWhere primitive (#540) does not
// return a deleted-row count, so the sweeper no longer publishes a
// rows-deleted counter — the upstream PR called out that a count
// would add a column to the receipt for limited operational value.
// The per-tick "sweep ran successfully" counter (identity_sweeper_
// runs_total) provides "the GC is alive" liveness; the error counter
// catches a stuck backend.
var (
	sweeperRuns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "identity_sweeper_runs_total",
			Help: "Sweep cycles completed by the identity GC sweeper, per node type. tenant-shard-db v1.14.0's OpDeleteWhere does not surface a deleted-row count, so this metric counts ticks (each tick deletes up to GATEWAY_SWEEPER_BATCH rows) rather than rows.",
		},
		[]string{"node_type"},
	)
	sweeperErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "identity_sweeper_errors_total",
			Help: "Sweep errors per node type. Skips against backends that return ErrSweepNotImplemented are NOT counted here.",
		},
		[]string{"node_type"},
	)
)

// initSweeperMetrics registers the sweeper counters with the default
// Prometheus registry. It is idempotent — repeated calls with the
// same metric vectors return without re-registering (testing.M and
// per-test app.New invocations both end up here).
//
// The function is package-private; the only caller is newSweeper.
var initSweeperMetricsOnce sync.Once

func initSweeperMetrics() {
	initSweeperMetricsOnce.Do(func() {
		// MustRegister panics on duplicate registration. We register
		// once per process; tests that build multiple app.New
		// instances are protected by the sync.Once.
		prometheus.DefaultRegisterer.MustRegister(sweeperRuns, sweeperErrors)
	})
}

// nodeTypeSweeper pairs a label value with the Repository call that
// deletes its expired rows. Adding a node type means one entry in
// targets() plus the matching Repository method.
type nodeTypeSweeper struct {
	name string
	fn   func(ctx context.Context, beforeMs int64, limit int) error
}

// accountPurger hard-deletes accounts whose self-service deletion grace window
// has elapsed. It is the service-level cascade (session/token revocation, the
// repo delete, and the downstream deprovision event), not a repo batch delete,
// so it does not fit the nodeTypeSweeper shape. Implemented by
// *service.AdminService; nil disables the account-deletion sweep.
type accountPurger interface {
	PurgeExpiredPendingDeletions(ctx context.Context, cutoffMs int64, limit int) (int, error)
}

// accountDeletionLabel is the metrics node_type label for the
// account-deletion purge step of a sweep cycle.
const accountDeletionLabel = "pending_deletion_users"

// auditRetentionLabel is the metrics node_type label for the audit-log
// retention step of a sweep cycle (GDPR Art 5(1)(e) storage limitation).
const auditRetentionLabel = "audit_events"

// deviceRetentionLabel is the metrics node_type label for the attested-device
// retention sweep. Like the audit sweep this is NOT an expiry target: a device
// row has no expires_at_ms, so it must never share the expiry cutoff.
const deviceRetentionLabel = "attested_devices"

// anonymousRetentionLabel is the metrics node_type label for the
// anonymous-user retention sweep. Like the device sweep it is NOT one of
// targets(): it keys on last activity, not on a row's own expires_at_ms.
const anonymousRetentionLabel = "anonymous_users"

// auditRetentionDay is the fixed-duration day used to turn the configured
// retention window (whole days) into a cutoff instant. A coarse retention
// window (months) needs no calendar/DST precision, so a flat 24h day matches
// the service layer's msPerDay multiplier.
const auditRetentionDay = 24 * time.Hour

// sweeper periodically deletes expired ephemeral rows in batches.
// One instance per app.New; started immediately and stopped via the
// returned cancel func.
type sweeper struct {
	repo     service.Repository
	purger   accountPurger
	logger   *zap.Logger
	interval time.Duration
	batch    int
	grace    time.Duration

	// auditRetentionDays bounds how long audit events are kept; each tick
	// deletes events older than now - auditRetentionDays. 0 (or negative)
	// disables the audit-retention step — the trail is kept forever.
	auditRetentionDays int
	// deviceRetentionDays bounds how long an attested device is kept after
	// its LAST USE. 0 (or negative) disables the step.
	deviceRetentionDays int
	// anonymousRetentionDays bounds how long an anonymous user is kept after
	// its last activity. Its own window, for the same reason the device one
	// is: an anonymous user row has no expires_at_ms to be slack past.
	anonymousRetentionDays int

	// now is the time source; tests override it. nil means time.Now.
	now func() time.Time

	// skipLogged tracks node types that have already logged the
	// "not implemented for this backend" notice, so a backend whose
	// sweep is permanently a no-op spams the log once per node type
	// for the lifetime of the process instead of every tick.
	skipLogged map[string]bool
	skipMu     sync.Mutex
}

// newSweeper constructs a sweeper from config. Returns nil when
// sweeping is disabled (interval <= 0); the caller must handle the
// nil case. purger may be nil to disable the account-deletion sweep.
// auditRetentionDays <= 0 disables the audit-retention step.
func newSweeper(repo service.Repository, purger accountPurger, intervalSec, batch, graceSec, auditRetentionDays, deviceRetentionDays, anonymousRetentionDays int, logger *zap.Logger) *sweeper {
	if intervalSec <= 0 {
		return nil
	}
	if batch <= 0 {
		batch = 500
	}
	if graceSec < 0 {
		graceSec = 0
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	initSweeperMetrics()
	return &sweeper{
		repo:                   repo,
		purger:                 purger,
		logger:                 logger,
		interval:               time.Duration(intervalSec) * time.Second,
		batch:                  batch,
		grace:                  time.Duration(graceSec) * time.Second,
		auditRetentionDays:     auditRetentionDays,
		deviceRetentionDays:    deviceRetentionDays,
		anonymousRetentionDays: anonymousRetentionDays,
		skipLogged:             make(map[string]bool, 5),
	}
}

// start launches the sweep loop in a background goroutine. The
// returned stop func cancels the context, waits for the goroutine to
// exit, and is safe to call multiple times.
func (s *sweeper) start() func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		t := time.NewTicker(s.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runOnce(ctx)
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

// runOnce executes one sweep cycle: for each node type, delete up to
// batch rows whose expires_at is older than (now - grace). Errors
// are logged and counted; the loop never aborts midway through the
// node-type list because one type failed.
func (s *sweeper) runOnce(ctx context.Context) {
	nowFn := s.now
	if nowFn == nil {
		nowFn = time.Now
	}
	beforeMs := nowFn().Add(-s.grace).UnixMilli()

	for _, t := range s.targets() {
		s.sweepType(ctx, t, beforeMs)
	}

	now := nowFn()
	s.purgeExpiredAccountDeletions(ctx, now.UnixMilli())
	s.sweepAuditRetention(ctx, now)
	s.sweepDeviceRetention(ctx, now)
	s.sweepAnonymousRetention(ctx, now)
}

// sweepAnonymousRetention deletes anonymous users whose LAST ACTIVITY
// predates the retention window (now - anonymousRetentionDays). Like the
// device sweep it does NOT ride the shared expiry cutoff: that cutoff is
// `now - grace` (default 60s) applied to a row's own expires_at_ms, and an
// anonymous user row has no expiry. Sharing it would delete every anonymous
// account about a minute after its last refresh — and since a refresh token
// is an anonymous account's ONLY credential, the session would be
// unrecoverable. No-op when retention is disabled (<= 0).
//
// SCOPE: like every sweep here, this runs against the repo bound to the
// boot-default project, so it reaps only that project's rows. In a
// control-plane deployment, anonymous users in OTHER projects are never
// reaped — and unlike the other tables, these rows are minted by an
// unauthenticated endpoint. Until a per-project sweep loop exists (rebinding
// via WithProject), a multi-project deployment should keep anonymous
// sign-in to the default project or reap those rows itself. ADR-0013
// records this in its Consequences and "Not shipped" list, and the
// docs-site Retention section and UPGRADE.md state it for operators.
func (s *sweeper) sweepAnonymousRetention(ctx context.Context, now time.Time) {
	if s.anonymousRetentionDays <= 0 {
		return
	}
	cutoffMs := now.Add(-time.Duration(s.anonymousRetentionDays) * auditRetentionDay).UnixMilli()
	if err := s.repo.DeleteStaleAnonymousUsers(ctx, cutoffMs, s.batch); err != nil {
		if errors.Is(err, service.ErrSweepNotImplemented) {
			s.logSkipOnce(anonymousRetentionLabel)
			return
		}
		sweeperErrors.WithLabelValues(anonymousRetentionLabel).Inc()
		s.logger.Warn(
			"sweeper_anonymous_retention_failed",
			zap.Int64("cutoff_ms", cutoffMs),
			zap.Int("retention_days", s.anonymousRetentionDays),
			zap.Error(err),
		)
		return
	}
	sweeperRuns.WithLabelValues(anonymousRetentionLabel).Inc()
}

// sweepDeviceRetention deletes attested devices whose LAST USE predates the
// retention window (now - deviceRetentionDays). It deliberately does NOT ride
// the expiry cutoff the targets() sweeps share: that cutoff is `now - grace`
// (default 60s), which is slack past a row's OWN expires_at_ms. A device row
// has no expiry — reaping one forces a full re-attestation, and Apple's
// attestKey may be called only once per generated key — so sharing the cutoff
// would erase the device registry roughly every tick and break refresh
// entirely. No-op when retention is disabled (deviceRetentionDays <= 0).
//
// SCOPE: like every sweep here, this runs against the repo bound to the
// boot-default project, so it reaps only that project's rows. Other
// projects' attested_devices are not reached (0027's FORCE ROW LEVEL
// SECURITY would refuse them anyway). That limitation is shared by all of
// targets() and predates assurance, but it matters more here: this is the
// first durable, never-expiring table on the list. A per-project sweep loop
// rebinding via WithProject is the fix when a deployment needs it.
func (s *sweeper) sweepDeviceRetention(ctx context.Context, now time.Time) {
	if s.deviceRetentionDays <= 0 {
		return
	}
	cutoffMs := now.Add(-time.Duration(s.deviceRetentionDays) * auditRetentionDay).UnixMilli()
	if err := s.repo.DeleteStaleAttestedDevices(ctx, cutoffMs, s.batch); err != nil {
		if errors.Is(err, service.ErrSweepNotImplemented) {
			s.logSkipOnce(deviceRetentionLabel)
			return
		}
		sweeperErrors.WithLabelValues(deviceRetentionLabel).Inc()
		s.logger.Warn(
			"sweeper_device_retention_failed",
			zap.Int64("cutoff_ms", cutoffMs),
			zap.Int("retention_days", s.deviceRetentionDays),
			zap.Error(err),
		)
		return
	}
	sweeperRuns.WithLabelValues(deviceRetentionLabel).Inc()
}

// sweepAuditRetention deletes audit events older than the retention window
// (now - auditRetentionDays), the GDPR Art 5(1)(e) storage-limitation step. It
// is a no-op when retention is disabled (auditRetentionDays <= 0): the operator
// has opted into keeping the trail forever. Errors are logged and counted; a
// failure never aborts the surrounding sweep cycle.
func (s *sweeper) sweepAuditRetention(ctx context.Context, now time.Time) {
	if s.auditRetentionDays <= 0 {
		return
	}
	cutoffMs := now.Add(-time.Duration(s.auditRetentionDays) * auditRetentionDay).UnixMilli()
	if _, err := s.repo.DeleteAuditEventsBefore(ctx, cutoffMs); err != nil {
		sweeperErrors.WithLabelValues(auditRetentionLabel).Inc()
		s.logger.Warn(
			"sweeper_audit_retention_failed",
			zap.Int64("cutoff_ms", cutoffMs),
			zap.Int("retention_days", s.auditRetentionDays),
			zap.Error(err),
		)
		return
	}
	sweeperRuns.WithLabelValues(auditRetentionLabel).Inc()
}

// purgeExpiredAccountDeletions hard-deletes accounts whose self-service
// deletion grace window has elapsed. The cutoff is `now` (not now - grace): the
// grace window is already baked into each account's deletion_scheduled_at_ms
// when the owner requested deletion, so an account is due exactly once its
// scheduled instant has passed. No-op when no purger is wired.
func (s *sweeper) purgeExpiredAccountDeletions(ctx context.Context, cutoffMs int64) {
	if s.purger == nil {
		return
	}
	if _, err := s.purger.PurgeExpiredPendingDeletions(ctx, cutoffMs, s.batch); err != nil {
		sweeperErrors.WithLabelValues(accountDeletionLabel).Inc()
		s.logger.Warn(
			"sweeper_account_deletion_failed",
			zap.Int64("cutoff_ms", cutoffMs),
			zap.Int("batch", s.batch),
			zap.Error(err),
		)
		return
	}
	sweeperRuns.WithLabelValues(accountDeletionLabel).Inc()
}

// targets returns the node-type sweepers in a deterministic order.
// Defined as a method rather than a package-level var because the
// function values close over s.repo.
func (s *sweeper) targets() []nodeTypeSweeper {
	return []nodeTypeSweeper{
		{"webauthn_challenges", s.repo.DeleteExpiredWebAuthnChallenges},
		{"email_verification_tokens", s.repo.DeleteExpiredEmailVerificationTokens},
		{"password_reset_tokens", s.repo.DeleteExpiredPasswordResetTokens},
		{"email_change_tokens", s.repo.DeleteExpiredEmailChangeTokens},
		{"login_challenges", s.repo.DeleteExpiredLoginChallenges},
		{"oauth_one_time_codes", s.repo.DeleteExpiredOAuthOneTimeCodes},
		{"sso_sessions", s.repo.DeleteExpiredSSOSessions},
		{"native_token_redemptions", s.repo.DeleteExpiredNativeTokenRedemptions},
		{"email_login_codes", s.repo.DeleteExpiredEmailLoginCodes},
		{"magic_link_tokens", s.repo.DeleteExpiredMagicLinkTokens},
		{"phone_verification_codes", s.repo.DeleteExpiredPhoneVerificationCodes},
		{"qr_login_sessions", s.repo.DeleteExpiredQrLoginSessions},
		{"user_invitations", s.repo.DeleteExpiredInvitations},
		{"assurance_challenges", s.repo.DeleteExpiredAssuranceChallenges},
	}
}

func (s *sweeper) sweepType(ctx context.Context, t nodeTypeSweeper, beforeMs int64) {
	if err := t.fn(ctx, beforeMs, s.batch); err != nil {
		if errors.Is(err, service.ErrSweepNotImplemented) {
			s.logSkipOnce(t.name)
			return
		}
		sweeperErrors.WithLabelValues(t.name).Inc()
		s.logger.Warn(
			"sweeper_delete_failed",
			zap.String("node_type", t.name),
			zap.Int64("before_ms", beforeMs),
			zap.Int("batch", s.batch),
			zap.Error(err),
		)
		return
	}
	sweeperRuns.WithLabelValues(t.name).Inc()
	s.logger.Debug(
		"sweeper_ran",
		zap.String("node_type", t.name),
		zap.Int64("before_ms", beforeMs),
		zap.Int("batch", s.batch),
	)
}

func (s *sweeper) logSkipOnce(nodeType string) {
	s.skipMu.Lock()
	defer s.skipMu.Unlock()
	if s.skipLogged[nodeType] {
		return
	}
	s.skipLogged[nodeType] = true
	s.logger.Info(
		"sweeper_skip_not_implemented",
		zap.String("node_type", nodeType),
		zap.String("reason", "backend does not implement the expired-row sweep; further per-tick skips are silent"),
	)
}
