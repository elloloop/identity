package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap/zaptest"

	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

// readCounter returns the current value of a Prometheus counter
// child without pulling in the heavier testutil package (which
// transitively brings godebug along — undesirable for a sweeper
// test that only needs a single float).
func readCounter(c prometheus.Counter) float64 {
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return -1
	}
	if m.Counter == nil || m.Counter.Value == nil {
		return 0
	}
	return *m.Counter.Value
}

// mockSweepRepo is a Repository stand-in that records sweep calls.
// It overrides every DeleteExpired* method the sweeper calls so the
// recorded count matches len(targets); embedding StubRepository covers
// the rest of the Repository surface with ErrServiceUnavailable.
type mockSweepRepo struct {
	service.StubRepository

	calls      atomic.Int64
	lastBefore atomic.Int64
	lastLimit  atomic.Int64

	// auditCalls/auditCutoff record the audit-retention sweep separately —
	// it has a distinct signature (a cutoff, no limit, a returned count) and
	// its own metrics label. auditErr, when set, is returned from it so the
	// audit-retention error path can be exercised independently of err.
	auditCalls  atomic.Int64
	auditCutoff atomic.Int64
	auditErr    error

	// err and skip control the per-method behaviour. err is returned
	// for every method when non-nil. skip causes every method to
	// return service.ErrSweepNotImplemented.
	err  error
	skip bool
}

func (m *mockSweepRepo) DeleteAuditEventsBefore(_ context.Context, cutoffMs int64) (int, error) {
	m.auditCalls.Add(1)
	m.auditCutoff.Store(cutoffMs)
	return 0, m.auditErr
}

func (m *mockSweepRepo) sweep(beforeMs int64, limit int) error {
	m.calls.Add(1)
	m.lastBefore.Store(beforeMs)
	m.lastLimit.Store(int64(limit))
	if m.skip {
		return service.ErrSweepNotImplemented
	}
	return m.err
}

func (m *mockSweepRepo) DeleteExpiredWebAuthnChallenges(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredEmailVerificationTokens(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredPasswordResetTokens(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredEmailChangeTokens(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredLoginChallenges(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredOAuthOneTimeCodes(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredNativeTokenRedemptions(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredEmailLoginCodes(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredMagicLinkTokens(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredPhoneVerificationCodes(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredQrLoginSessions(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredInvitations(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteExpiredAssuranceChallenges(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func (m *mockSweepRepo) DeleteStaleAttestedDevices(_ context.Context, b int64, l int) error {
	return m.sweep(b, l)
}

func TestSweeper_DisabledWhenIntervalIsZero(t *testing.T) {
	logger := zaptest.NewLogger(t)
	s := newSweeper(&mockSweepRepo{}, nil, 0, 100, 30, 0, 0, logger)
	if s != nil {
		t.Fatal("interval=0 must yield a nil sweeper (sweep disabled)")
	}
}

func TestSweeper_DisabledWhenIntervalNegative(t *testing.T) {
	logger := zaptest.NewLogger(t)
	s := newSweeper(&mockSweepRepo{}, nil, -1, 100, 30, 0, 0, logger)
	if s != nil {
		t.Fatal("interval<0 must yield a nil sweeper (sweep disabled)")
	}
}

func TestSweeper_RunOnceCallsEveryMethod(t *testing.T) {
	repo := &mockSweepRepo{}
	logger := zaptest.NewLogger(t)
	s := newSweeper(repo, nil, 1, 50, 30, 0, 0, logger)
	if s == nil {
		t.Fatal("newSweeper returned nil with positive interval")
	}

	fixedNow := time.UnixMilli(1_700_000_000_000)
	s.now = func() time.Time { return fixedNow }

	s.runOnce(context.Background())

	if got, want := repo.calls.Load(), int64(len(s.targets())); got != want {
		t.Fatalf("expected %d sweep calls (one per node type), got %d", want, got)
	}
	expectedBefore := fixedNow.Add(-30 * time.Second).UnixMilli()
	if got := repo.lastBefore.Load(); got != expectedBefore {
		t.Fatalf("lastBefore = %d, want %d (now - grace)", got, expectedBefore)
	}
	if got := repo.lastLimit.Load(); got != 50 {
		t.Fatalf("lastLimit = %d, want 50 (batch)", got)
	}
}

// mockPurger records the account-deletion purge calls the sweeper makes.
type mockPurger struct {
	calls      atomic.Int64
	lastCutoff atomic.Int64
	lastLimit  atomic.Int64
	err        error
}

func (m *mockPurger) PurgeExpiredPendingDeletions(_ context.Context, cutoffMs int64, limit int) (int, error) {
	m.calls.Add(1)
	m.lastCutoff.Store(cutoffMs)
	m.lastLimit.Store(int64(limit))
	return 0, m.err
}

func TestSweeper_RunOncePurgesExpiredAccountDeletions(t *testing.T) {
	repo := &mockSweepRepo{}
	purger := &mockPurger{}
	logger := zaptest.NewLogger(t)
	s := newSweeper(repo, purger, 1, 50, 30, 0, 0, logger)

	fixedNow := time.UnixMilli(1_700_000_000_000)
	s.now = func() time.Time { return fixedNow }

	s.runOnce(context.Background())

	if got := purger.calls.Load(); got != 1 {
		t.Fatalf("purger called %d times, want 1", got)
	}
	// The account-deletion cutoff is `now` (the grace is already baked into
	// each account's scheduled instant), NOT now - sweeper grace.
	if got, want := purger.lastCutoff.Load(), fixedNow.UnixMilli(); got != want {
		t.Fatalf("purge cutoff = %d, want %d (now)", got, want)
	}
	if got := purger.lastLimit.Load(); got != 50 {
		t.Fatalf("purge limit = %d, want 50 (batch)", got)
	}
}

func TestSweeper_NilPurgerSkipsAccountDeletion(t *testing.T) {
	repo := &mockSweepRepo{}
	logger := zaptest.NewLogger(t)
	s := newSweeper(repo, nil, 1, 50, 30, 0, 0, logger)
	// Must not panic when no purger is wired.
	s.runOnce(context.Background())
}

func TestSweeper_PurgeErrorIncrementsErrorCounter(t *testing.T) {
	repo := &mockSweepRepo{}
	purger := &mockPurger{err: errors.New("boom")}
	logger := zaptest.NewLogger(t)
	initSweeperMetrics()
	baseline := readCounter(sweeperErrors.WithLabelValues(accountDeletionLabel))

	s := newSweeper(repo, purger, 1, 50, 30, 0, 0, logger)
	s.runOnce(context.Background())

	got := readCounter(sweeperErrors.WithLabelValues(accountDeletionLabel))
	if got != baseline+1 {
		t.Fatalf("expected account-deletion errors counter +1, got %v -> %v", baseline, got)
	}
}

func TestSweeper_SkipNotImplementedLogsOncePerNodeType(t *testing.T) {
	repo := &mockSweepRepo{skip: true}
	logger := zaptest.NewLogger(t)
	s := newSweeper(repo, nil, 1, 50, 30, 0, 0, logger)

	// Run three ticks; we must only log skip once per node type.
	for i := 0; i < 3; i++ {
		s.runOnce(context.Background())
	}

	// Every node type should be in the logged-once map exactly once.
	s.skipMu.Lock()
	defer s.skipMu.Unlock()
	if got, want := len(s.skipLogged), len(s.targets()); got != want {
		t.Fatalf("expected %d skip-logged entries, got %d", want, got)
	}
}

func TestSweeper_SkipNotImplementedDoesNotIncrementErrors(t *testing.T) {
	repo := &mockSweepRepo{skip: true}
	logger := zaptest.NewLogger(t)
	initSweeperMetrics()
	baseline := readCounter(sweeperErrors.WithLabelValues("webauthn_challenges"))

	s := newSweeper(repo, nil, 1, 50, 30, 0, 0, logger)
	s.runOnce(context.Background())

	got := readCounter(sweeperErrors.WithLabelValues("webauthn_challenges"))
	if got != baseline {
		t.Fatalf("ErrSweepNotImplemented incremented errors counter: %v -> %v", baseline, got)
	}
}

func TestSweeper_RealErrorIncrementsErrorCounter(t *testing.T) {
	repo := &mockSweepRepo{err: errors.New("boom")}
	logger := zaptest.NewLogger(t)
	initSweeperMetrics()

	baseline := readCounter(sweeperErrors.WithLabelValues("password_reset_tokens"))

	s := newSweeper(repo, nil, 1, 50, 30, 0, 0, logger)
	s.runOnce(context.Background())

	got := readCounter(sweeperErrors.WithLabelValues("password_reset_tokens"))
	if got != baseline+1 {
		t.Fatalf("expected errors counter +1, got %v -> %v", baseline, got)
	}
}

// TestSweeper_SuccessfulRunIncrementsRunsCounter asserts that each
// per-node-type sweep tick bumps identity_sweeper_runs_total{node_type}.
// tenant-shard-db v1.14.0's OpDeleteWhere does not return a deleted-
// row count, so the previous identity_sweeper_deleted_total metric
// (rows-deleted, per node type) was replaced by this per-tick
// counter — it preserves the "GC is alive" liveness signal without
// claiming a count the upstream can't provide.
func TestSweeper_SuccessfulRunIncrementsRunsCounter(t *testing.T) {
	repo := &mockSweepRepo{}
	logger := zaptest.NewLogger(t)
	initSweeperMetrics()
	baseline := readCounter(sweeperRuns.WithLabelValues("login_challenges"))

	s := newSweeper(repo, nil, 1, 50, 30, 0, 0, logger)
	s.runOnce(context.Background())

	got := readCounter(sweeperRuns.WithLabelValues("login_challenges"))
	if got != baseline+1 {
		t.Fatalf("expected runs counter +1, got %v -> %v", baseline, got)
	}
}

func TestSweeper_RetentionDisabledSkipsAuditSweep(t *testing.T) {
	repo := &mockSweepRepo{}
	logger := zaptest.NewLogger(t)
	// auditRetentionDays = 0 → retention disabled: the audit sweep is a no-op.
	s := newSweeper(repo, nil, 1, 50, 30, 0, 0, logger)

	s.runOnce(context.Background())

	if got := repo.auditCalls.Load(); got != 0 {
		t.Fatalf("audit sweep called %d times with retention disabled, want 0", got)
	}
}

func TestSweeper_RetentionNegativeSkipsAuditSweep(t *testing.T) {
	repo := &mockSweepRepo{}
	logger := zaptest.NewLogger(t)
	s := newSweeper(repo, nil, 1, 50, 30, -5, 0, logger)

	s.runOnce(context.Background())

	if got := repo.auditCalls.Load(); got != 0 {
		t.Fatalf("audit sweep called %d times with negative retention, want 0", got)
	}
}

func TestSweeper_RetentionEnabledSweepsAtCutoff(t *testing.T) {
	repo := &mockSweepRepo{}
	logger := zaptest.NewLogger(t)
	const retentionDays = 30
	s := newSweeper(repo, nil, 1, 50, 30, retentionDays, 0, logger)

	fixedNow := time.UnixMilli(1_700_000_000_000)
	s.now = func() time.Time { return fixedNow }

	s.runOnce(context.Background())

	if got := repo.auditCalls.Load(); got != 1 {
		t.Fatalf("audit sweep called %d times, want 1", got)
	}
	// The cutoff is now - retentionDays (a flat 24h day), NOT now - sweeper grace.
	wantCutoff := fixedNow.Add(-retentionDays * 24 * time.Hour).UnixMilli()
	if got := repo.auditCutoff.Load(); got != wantCutoff {
		t.Fatalf("audit cutoff = %d, want %d (now - %d days)", got, wantCutoff, retentionDays)
	}
}

func TestSweeper_AuditRetentionSuccessIncrementsRunsCounter(t *testing.T) {
	repo := &mockSweepRepo{}
	logger := zaptest.NewLogger(t)
	initSweeperMetrics()
	baseline := readCounter(sweeperRuns.WithLabelValues(auditRetentionLabel))

	s := newSweeper(repo, nil, 1, 50, 30, 30, 0, logger)
	s.runOnce(context.Background())

	got := readCounter(sweeperRuns.WithLabelValues(auditRetentionLabel))
	if got != baseline+1 {
		t.Fatalf("expected audit-retention runs counter +1, got %v -> %v", baseline, got)
	}
}

func TestSweeper_AuditRetentionErrorIncrementsErrorCounter(t *testing.T) {
	repo := &mockSweepRepo{auditErr: errors.New("boom")}
	logger := zaptest.NewLogger(t)
	initSweeperMetrics()
	baseline := readCounter(sweeperErrors.WithLabelValues(auditRetentionLabel))

	s := newSweeper(repo, nil, 1, 50, 30, 30, 0, logger)
	s.runOnce(context.Background())

	got := readCounter(sweeperErrors.WithLabelValues(auditRetentionLabel))
	if got != baseline+1 {
		t.Fatalf("expected audit-retention errors counter +1, got %v -> %v", baseline, got)
	}
}

// TestSweeper_RetentionDeletesOnlyPastCutoff drives the retention step end to
// end against a real in-memory repository: a tick must delete audit events
// older than now - retentionDays and keep newer ones, and a disabled sweep
// must leave every event in place.
func TestSweeper_RetentionDeletesOnlyPastCutoff(t *testing.T) {
	ctx := context.Background()
	logger := zaptest.NewLogger(t)
	const retentionDays = 30
	day := 24 * time.Hour
	fixedNow := time.UnixMilli(1_700_000_000_000)
	cutoffMs := fixedNow.Add(-retentionDays * day).UnixMilli()

	const actor = "audit-retention-user"
	seed := func(repo *memory.Repo) {
		events := []*service.AuditEvent{
			{EventType: "stale", ActorUserID: actor, TargetUserID: actor, CreatedAt: cutoffMs - day.Milliseconds()},
			{EventType: "boundary", ActorUserID: actor, TargetUserID: actor, CreatedAt: cutoffMs},
			{EventType: "fresh", ActorUserID: actor, TargetUserID: actor, CreatedAt: fixedNow.Add(-day).UnixMilli()},
		}
		for i, e := range events {
			if _, err := repo.CreateAuditEvent(ctx, e); err != nil {
				t.Fatalf("seed audit event[%d]: %v", i, err)
			}
		}
	}

	t.Run("enabled deletes only stale", func(t *testing.T) {
		repo := memory.New()
		seed(repo)
		s := newSweeper(repo, nil, 1, 50, 30, retentionDays, 0, logger)
		s.now = func() time.Time { return fixedNow }

		s.runOnce(ctx)

		got, err := repo.ListAuditEventsForUser(ctx, actor, 50)
		if err != nil {
			t.Fatalf("ListAuditEventsForUser: %v", err)
		}
		// The stale event (older than the cutoff) is gone; the boundary event
		// (exactly at the cutoff, so not strictly older) and the fresh event stay.
		if len(got) != 2 {
			t.Fatalf("after sweep: %d events, want 2 (boundary + fresh): %+v", len(got), got)
		}
		for _, e := range got {
			if e.EventType == "stale" {
				t.Fatalf("stale event survived retention sweep: %+v", e)
			}
		}
	})

	t.Run("disabled keeps everything", func(t *testing.T) {
		repo := memory.New()
		seed(repo)
		s := newSweeper(repo, nil, 1, 50, 30, 0, 0, logger)
		s.now = func() time.Time { return fixedNow }

		s.runOnce(ctx)

		got, err := repo.ListAuditEventsForUser(ctx, actor, 50)
		if err != nil {
			t.Fatalf("ListAuditEventsForUser: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("retention disabled must keep all events, got %d: %+v", len(got), got)
		}
	})
}

func TestSweeper_StartStopCleanly(t *testing.T) {
	repo := &mockSweepRepo{}
	logger := zaptest.NewLogger(t)

	// A very short interval lets the loop tick at least once before
	// we shut it down. The test asserts the stop func returns
	// promptly rather than races the still-running goroutine.
	s := newSweeper(repo, nil, 1, 50, 30, 0, 0, logger)
	stop := s.start()

	// Allow a couple of ticks. We don't assert exact tick counts —
	// runtime jitter on a busy CI runner makes that flaky. The
	// guarantee under test is: stop() returns.
	time.Sleep(2200 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop() did not return within 5s")
	}

	// Second stop() must be safe (idempotent).
	stop()
}

// TestSweeperTargetsCoverEveryRepositorySweep is the guard the
// assurance-challenges omission proved necessary: a DeleteExpired* method
// can be declared on service.Repository, implemented in every driver, and
// conformance-tested — and still never run in production if it is absent
// from targets(). Pin the wiring by NAME so adding a Repository sweep
// without wiring it here fails loudly.
//
// The invariant is specifically: every table with an expires_at_ms rides
// the shared EXPIRY cutoff (now - grace, slack past a row's own expiry).
// A table governed by a RETENTION window instead — audit_events,
// attested_devices — must NOT be here: it needs its own cutoff, and
// sharing this one would reap it against the 60s grace.
func TestSweeperTargetsCoverEveryRepositorySweep(t *testing.T) {
	s := &sweeper{repo: &mockSweepRepo{}}
	names := map[string]bool{}
	for _, tgt := range s.targets() {
		names[tgt.name] = true
	}
	// One entry per DeleteExpired* method on service.Repository. Update
	// this list in the same change that adds the Repository method.
	want := []string{
		"webauthn_challenges",
		"email_verification_tokens",
		"password_reset_tokens",
		"email_change_tokens",
		"login_challenges",
		"oauth_one_time_codes",
		"native_token_redemptions",
		"email_login_codes",
		"magic_link_tokens",
		"phone_verification_codes",
		"qr_login_sessions",
		"user_invitations",
		"assurance_challenges",
	}
	for _, w := range want {
		if !names[w] {
			t.Errorf("sweeper.targets() is missing %q — the table will grow unbounded", w)
		}
	}
	if len(names) != len(want) {
		t.Errorf("targets() has %d entries, want %d — update this guard alongside targets()", len(names), len(want))
	}
}

// TestSweeper_DeviceRetentionUsesItsOwnCutoff is the regression guard for a
// real defect: attested_devices was briefly wired into targets(), so it was
// reaped against the shared EXPIRY cutoff (now - grace, default 60s) rather
// than a retention window. Every device then died about a minute after its
// last use, which breaks RefreshAssuranceToken permanently — and because
// Apple's attestKey may be called only once per generated key, a client that
// persists its Secure Enclave key cannot even re-attest its way out.
//
// Driven at PRODUCTION defaults (grace 60s, batch 500) so the test fails if
// the two cutoffs are ever conflated again.
func TestSweeper_DeviceRetentionUsesItsOwnCutoff(t *testing.T) {
	const (
		graceSeconds  = 60 // GATEWAY_SWEEPER_GRACE_SECONDS default
		retentionDays = 90 // GATEWAY_ASSURANCE_DEVICE_RETENTION_DAYS default
	)
	repo := &recordingDeviceSweepRepo{}
	s := newSweeper(repo, nil, 1, 500, graceSeconds, 0, retentionDays, zaptest.NewLogger(t))

	now := time.UnixMilli(1_800_000_000_000)
	s.now = func() time.Time { return now }
	s.runOnce(context.Background())

	if repo.deviceCalls != 1 {
		t.Fatalf("device retention sweep ran %d times, want 1", repo.deviceCalls)
	}
	// The cutoff must be the RETENTION window, not now - grace.
	wantCutoff := now.Add(-retentionDays * 24 * time.Hour).UnixMilli()
	if repo.deviceCutoff != wantCutoff {
		t.Fatalf("device cutoff = %d, want %d (now - %dd). A cutoff of %d (now - grace) "+
			"would delete every device ~%ds after its last use and break refresh.",
			repo.deviceCutoff, wantCutoff, retentionDays,
			now.Add(-graceSeconds*time.Second).UnixMilli(), graceSeconds)
	}

	// Concretely: a device used 10 minutes ago survives; one used 100 days
	// ago does not.
	recent := now.Add(-10 * time.Minute).UnixMilli()
	ancient := now.Add(-100 * 24 * time.Hour).UnixMilli()
	if recent < repo.deviceCutoff {
		t.Errorf("a device last used 10 minutes ago would be reaped")
	}
	if ancient >= repo.deviceCutoff {
		t.Errorf("a device last used 100 days ago would survive")
	}

	t.Run("retention disabled skips the sweep entirely", func(t *testing.T) {
		r := &recordingDeviceSweepRepo{}
		s := newSweeper(r, nil, 1, 500, graceSeconds, 0, 0, zaptest.NewLogger(t))
		s.now = func() time.Time { return now }
		s.runOnce(context.Background())
		if r.deviceCalls != 0 {
			t.Fatalf("device sweep ran %d times with retention disabled", r.deviceCalls)
		}
	})
}

// recordingDeviceSweepRepo records the cutoff the device-retention sweep is
// given, separately from the shared expiry cutoff.
type recordingDeviceSweepRepo struct {
	mockSweepRepo
	deviceCalls  int
	deviceCutoff int64
}

func (m *recordingDeviceSweepRepo) DeleteStaleAttestedDevices(_ context.Context, beforeMs int64, _ int) error {
	m.deviceCalls++
	m.deviceCutoff = beforeMs
	return nil
}
