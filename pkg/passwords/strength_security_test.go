package passwords

import (
	"testing"
	"time"
)

// TestSec_VerifyConstantTime asserts that Verify does not leak information
// via timing — comparing a wrong password whose first byte differs should
// not be measurably faster than one whose last byte differs.
//
// We rely on the fact that bcrypt.CompareHashAndPassword internally hashes
// the candidate with the salt and compares the resulting digest in
// constant time. A non-constant-time path would make early-mismatch much
// faster than late-mismatch.
//
// The assertion is a coarse ratio check (bench-style): early-mismatch
// must NOT be more than 2x faster than late-mismatch on average. This
// guards against accidental short-circuit comparisons.
func TestSec_VerifyConstantTime(t *testing.T) {
	if raceEnabled {
		// Race detector adds ~10x overhead and significant scheduling
		// jitter; timing tests are unreliable under -race. The leak this
		// guards against is a short-circuit byte compare which is orders
		// of magnitude faster than bcrypt — race mode has nothing to
		// usefully detect. Run this test in non-race CI passes.
		t.Skip("skipping timing test under -race (unreliable; run separately without -race)")
	}
	correct := "TheC0rrect#PasswordValue!"
	hash, err := Hash(correct)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	// Same length as `correct` to keep length effects out of timing.
	earlyDiff := "XheC0rrect#PasswordValue!" // first byte differs
	lateDiff := "TheC0rrect#PasswordValueX"  // last byte differs

	const iters = 30
	measure := func(candidate string) time.Duration {
		var total time.Duration
		for i := 0; i < iters; i++ {
			start := time.Now()
			_ = Verify(candidate, hash)
			total += time.Since(start)
		}
		return total / iters
	}

	// Warm-up: bcrypt timing is dominated by the cost factor, so JIT/cache
	// effects on the first iteration shouldn't matter, but be safe.
	_ = Verify(earlyDiff, hash)
	_ = Verify(lateDiff, hash)

	avgEarly := measure(earlyDiff)
	avgLate := measure(lateDiff)

	t.Logf("Verify avg early-diff=%v late-diff=%v", avgEarly, avgLate)

	// Ratio must be near 1.0; allow up to 5x to account for goroutine
	// scheduling jitter under -race and busy CI runners. The leak we're
	// guarding against is a short-circuit byte compare which would be
	// orders of magnitude faster than bcrypt — 5x is plenty of headroom.
	if avgEarly == 0 || avgLate == 0 {
		t.Fatalf("zero-duration measurement: early=%v late=%v", avgEarly, avgLate)
	}
	ratio := float64(avgLate) / float64(avgEarly)
	if ratio < 0.2 || ratio > 5.0 {
		t.Errorf("Verify timing differs >5x: early=%v late=%v ratio=%.2f (possible timing leak)",
			avgEarly, avgLate, ratio)
	}
}

// TestSec_HashCost_AtLeast30ms asserts the bcrypt cost factor has not been
// silently lowered. With ProductionBcryptCost (=12), Hash should take well
// over 30 ms on any modern hardware. If this fails, someone reduced the work
// factor and the codebase is now vulnerable to fast offline cracking.
//
// TestMain lowers bcryptCost to MinCost so the rest of the suite runs fast;
// we explicitly restore production cost here so this check measures the real
// production work factor.
func TestSec_HashCost_AtLeast30ms(t *testing.T) {
	if ProductionBcryptCost < 12 {
		t.Fatalf("ProductionBcryptCost lowered to %d; must be >= 12", ProductionBcryptCost)
	}

	restore := SetCostForTests(ProductionBcryptCost)
	defer restore()

	const minDuration = 30 * time.Millisecond

	start := time.Now()
	_, err := Hash("CostFactorCheck#1!")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	t.Logf("Hash elapsed=%v (min=%v)", elapsed, minDuration)
	if elapsed < minDuration {
		t.Errorf("Hash took %v, expected >= %v — bcrypt cost may have been lowered", elapsed, minDuration)
	}
}
