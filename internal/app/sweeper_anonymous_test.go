package app

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// recordingAnonSweepRepo records the cutoff the anonymous-retention sweep is
// given, separately from the shared expiry cutoff.
type recordingAnonSweepRepo struct {
	mockSweepRepo
	anonCalls  int
	anonCutoff int64
	anonLimit  int
}

func (m *recordingAnonSweepRepo) DeleteStaleAnonymousUsers(_ context.Context, beforeMs int64, limit int) error {
	m.anonCalls++
	m.anonCutoff = beforeMs
	m.anonLimit = limit
	return nil
}

// TestSweeper_AnonymousRetentionIsWiredAndUsesItsOwnCutoff guards the two
// failure modes this sweep has, both of which have real precedent in this
// repo.
//
// Not wired at all: DeleteExpiredAssuranceChallenges was implemented in every
// driver, conformance-tested and indexed, but never called — so the table grew
// without bound. An anonymous-user table would do the same, one row per app
// install, forever.
//
// Wired to the WRONG cutoff: attested_devices was briefly swept against the
// shared EXPIRY cutoff (now - grace, default 60s) instead of a retention
// window, which deleted every device about a minute after its last use. The
// same mistake here is worse: a refresh token is an anonymous account's ONLY
// credential, so reaping the user destroys a session the client still holds
// and cannot re-establish under the same id.
//
// Driven at PRODUCTION defaults so a regression fails here rather than in
// somebody's deployment.
func TestSweeper_AnonymousRetentionIsWiredAndUsesItsOwnCutoff(t *testing.T) {
	const (
		graceSeconds  = 60 // GATEWAY_SWEEPER_GRACE_SECONDS default
		batch         = 500
		retentionDays = 30 // GATEWAY_ANONYMOUS_RETENTION_DAYS default
	)
	repo := &recordingAnonSweepRepo{}
	s := newSweeper(repo, nil, 1, batch, graceSeconds, 0, 0, retentionDays, zaptest.NewLogger(t))

	now := time.UnixMilli(1_800_000_000_000)
	s.now = func() time.Time { return now }
	s.runOnce(context.Background())

	if repo.anonCalls != 1 {
		t.Fatalf("anonymous retention sweep ran %d times, want 1 — an unwired sweep grows the users table forever", repo.anonCalls)
	}
	if repo.anonLimit != batch {
		t.Errorf("sweep limit = %d, want the configured batch %d", repo.anonLimit, batch)
	}

	wantCutoff := now.Add(-retentionDays * 24 * time.Hour).UnixMilli()
	if repo.anonCutoff != wantCutoff {
		t.Fatalf("anonymous cutoff = %d, want %d (now - %dd). A cutoff of %d (now - grace) "+
			"would delete every anonymous account ~%ds after its last refresh, destroying "+
			"sessions whose refresh token is their only credential.",
			repo.anonCutoff, wantCutoff, retentionDays,
			now.Add(-graceSeconds*time.Second).UnixMilli(), graceSeconds)
	}

	// Concretely, at defaults: an account that refreshed a minute ago
	// survives; one idle for 60 days does not.
	justRefreshed := now.Add(-time.Minute).UnixMilli()
	longIdle := now.Add(-60 * 24 * time.Hour).UnixMilli()
	if justRefreshed < repo.anonCutoff {
		t.Error("an anonymous account that refreshed one minute ago would be reaped")
	}
	if longIdle >= repo.anonCutoff {
		t.Error("an anonymous account idle for 60 days would survive")
	}

	t.Run("retention disabled skips the sweep entirely", func(t *testing.T) {
		r := &recordingAnonSweepRepo{}
		s := newSweeper(r, nil, 1, batch, graceSeconds, 0, 0, 0, zaptest.NewLogger(t))
		s.now = func() time.Time { return now }
		s.runOnce(context.Background())
		if r.anonCalls != 0 {
			t.Fatalf("anonymous sweep ran %d times with retention disabled", r.anonCalls)
		}
	})

	t.Run("the anonymous sweep is not one of targets()", func(t *testing.T) {
		// targets() entries all ride the shared expiry cutoff. Membership
		// there is exactly the bug this test exists to prevent, so assert the
		// absence rather than trusting the cutoff check alone.
		for _, tgt := range s.targets() {
			if tgt.name == anonymousRetentionLabel {
				t.Fatalf("%q is in targets() — it would be swept against the expiry cutoff", tgt.name)
			}
		}
	})
}
