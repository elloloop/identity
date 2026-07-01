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

	// err and skip control the per-method behaviour. err is returned
	// for every method when non-nil. skip causes every method to
	// return service.ErrSweepNotImplemented.
	err  error
	skip bool
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

func TestSweeper_DisabledWhenIntervalIsZero(t *testing.T) {
	logger := zaptest.NewLogger(t)
	s := newSweeper(&mockSweepRepo{}, 0, 100, 30, logger)
	if s != nil {
		t.Fatal("interval=0 must yield a nil sweeper (sweep disabled)")
	}
}

func TestSweeper_DisabledWhenIntervalNegative(t *testing.T) {
	logger := zaptest.NewLogger(t)
	s := newSweeper(&mockSweepRepo{}, -1, 100, 30, logger)
	if s != nil {
		t.Fatal("interval<0 must yield a nil sweeper (sweep disabled)")
	}
}

func TestSweeper_RunOnceCallsEveryMethod(t *testing.T) {
	repo := &mockSweepRepo{}
	logger := zaptest.NewLogger(t)
	s := newSweeper(repo, 1, 50, 30, logger)
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

func TestSweeper_SkipNotImplementedLogsOncePerNodeType(t *testing.T) {
	repo := &mockSweepRepo{skip: true}
	logger := zaptest.NewLogger(t)
	s := newSweeper(repo, 1, 50, 30, logger)

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

	s := newSweeper(repo, 1, 50, 30, logger)
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

	s := newSweeper(repo, 1, 50, 30, logger)
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

	s := newSweeper(repo, 1, 50, 30, logger)
	s.runOnce(context.Background())

	got := readCounter(sweeperRuns.WithLabelValues("login_challenges"))
	if got != baseline+1 {
		t.Fatalf("expected runs counter +1, got %v -> %v", baseline, got)
	}
}

func TestSweeper_StartStopCleanly(t *testing.T) {
	repo := &mockSweepRepo{}
	logger := zaptest.NewLogger(t)

	// A very short interval lets the loop tick at least once before
	// we shut it down. The test asserts the stop func returns
	// promptly rather than races the still-running goroutine.
	s := newSweeper(repo, 1, 50, 30, logger)
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
