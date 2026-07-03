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

// sweeper periodically deletes expired ephemeral rows in batches.
// One instance per app.New; started immediately and stopped via the
// returned cancel func.
type sweeper struct {
	repo     service.Repository
	logger   *zap.Logger
	interval time.Duration
	batch    int
	grace    time.Duration

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
// nil case.
func newSweeper(repo service.Repository, intervalSec, batch, graceSec int, logger *zap.Logger) *sweeper {
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
		repo:       repo,
		logger:     logger,
		interval:   time.Duration(intervalSec) * time.Second,
		batch:      batch,
		grace:      time.Duration(graceSec) * time.Second,
		skipLogged: make(map[string]bool, 5),
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
		{"native_token_redemptions", s.repo.DeleteExpiredNativeTokenRedemptions},
		{"email_login_codes", s.repo.DeleteExpiredEmailLoginCodes},
		{"magic_link_tokens", s.repo.DeleteExpiredMagicLinkTokens},
		{"phone_verification_codes", s.repo.DeleteExpiredPhoneVerificationCodes},
		{"qr_login_sessions", s.repo.DeleteExpiredQrLoginSessions},
		{"user_invitations", s.repo.DeleteExpiredInvitations},
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
