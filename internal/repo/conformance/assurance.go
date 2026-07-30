package conformance

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runAssuranceConformance pins the assurance-storage semantics every
// driver must share: per-project key-id uniqueness on attested devices,
// CAS-guarded strictly-increasing sign counters (including under a
// concurrent fan-out — exactly one racer may win each step), and
// atomic single-use challenge consumption.
func runAssuranceConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/AttestedDeviceCRUD", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		got, err := r.GetAttestedDeviceByKeyID(ctx, "no-such-key")
		if err != nil || got != nil {
			t.Fatalf("GetAttestedDeviceByKeyID absent = (%#v, %v), want (nil, nil)", got, err)
		}

		d := &service.AttestedDeviceRecord{
			Platform:      "ios",
			KeyID:         "key-1",
			PublicKeySPKI: "c3BraQ==",
			SignCount:     0,
			Environment:   "production",
			CreatedAt:     1000,
			LastUsedAt:    1000,
		}
		id, err := r.CreateAttestedDevice(ctx, d)
		if err != nil || id == "" {
			t.Fatalf("CreateAttestedDevice = (%q, %v)", id, err)
		}

		got, err = r.GetAttestedDeviceByKeyID(ctx, "key-1")
		if err != nil || got == nil {
			t.Fatalf("GetAttestedDeviceByKeyID = (%#v, %v)", got, err)
		}
		if got.NodeID != id || got.Platform != "ios" || got.PublicKeySPKI != "c3BraQ==" ||
			got.SignCount != 0 || got.Environment != "production" ||
			got.CreatedAt != 1000 || got.LastUsedAt != 1000 {
			t.Fatalf("round-trip mismatch: %#v", got)
		}
	})

	t.Run(driver.Name+"/AttestedDeviceKeyIDUnique", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		if _, err := r.CreateAttestedDevice(ctx, &service.AttestedDeviceRecord{
			Platform: "ios", KeyID: "dup-key", PublicKeySPKI: "a", CreatedAt: 1, LastUsedAt: 1,
		}); err != nil {
			t.Fatalf("first create: %v", err)
		}
		_, err := r.CreateAttestedDevice(ctx, &service.AttestedDeviceRecord{
			Platform: "ios", KeyID: "dup-key", PublicKeySPKI: "b", CreatedAt: 2, LastUsedAt: 2,
		})
		if !errors.Is(err, service.ErrAlreadyExists) {
			t.Fatalf("duplicate key-id err = %v, want ErrAlreadyExists", err)
		}
	})

	t.Run(driver.Name+"/AttestedDeviceCounterCAS", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		d := &service.AttestedDeviceRecord{
			Platform: "ios", KeyID: "cas-key", PublicKeySPKI: "k", CreatedAt: 1, LastUsedAt: 1,
		}
		id, err := r.CreateAttestedDevice(ctx, d)
		if err != nil {
			t.Fatalf("create: %v", err)
		}

		// Winning CAS: 0 -> 5.
		if err := r.UpdateAttestedDeviceCounter(ctx, id, 0, 5, 2000); err != nil {
			t.Fatalf("CAS 0->5: %v", err)
		}
		got, err := r.GetAttestedDeviceByKeyID(ctx, "cas-key")
		if err != nil || got == nil {
			t.Fatalf("get after CAS: (%#v, %v)", got, err)
		}
		if got.SignCount != 5 || got.LastUsedAt != 2000 {
			t.Fatalf("after CAS: SignCount=%d LastUsedAt=%d, want 5/2000", got.SignCount, got.LastUsedAt)
		}

		// Losing CAS: expected 0 but stored is 5.
		if err := r.UpdateAttestedDeviceCounter(ctx, id, 0, 9, 3000); !errors.Is(err, service.ErrCounterStale) {
			t.Fatalf("stale CAS err = %v, want ErrCounterStale", err)
		}
		// The losing CAS must not have modified anything.
		got, _ = r.GetAttestedDeviceByKeyID(ctx, "cas-key")
		if got.SignCount != 5 || got.LastUsedAt != 2000 {
			t.Fatalf("losing CAS mutated the record: %#v", got)
		}

		// Missing device is distinguishable from a lost race.
		if err := r.UpdateAttestedDeviceCounter(ctx, "no-such-device", 0, 1, 1); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("missing device err = %v, want ErrNotFound", err)
		}
	})

	t.Run(driver.Name+"/AttestedDeviceCounterConcurrent", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		id, err := r.CreateAttestedDevice(ctx, &service.AttestedDeviceRecord{
			Platform: "ios", KeyID: "race-key", PublicKeySPKI: "k", CreatedAt: 1, LastUsedAt: 1,
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}

		// N racers all try the same 0 -> 1 step; the CAS admits exactly one.
		const racers = 8
		var wg sync.WaitGroup
		wins := make(chan struct{}, racers)
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := r.UpdateAttestedDeviceCounter(ctx, id, 0, 1, 2000)
				switch {
				case err == nil:
					wins <- struct{}{}
				case errors.Is(err, service.ErrCounterStale):
				default:
					t.Errorf("unexpected CAS error: %v", err)
				}
			}()
		}
		wg.Wait()
		close(wins)
		won := 0
		for range wins {
			won++
		}
		if won != 1 {
			t.Fatalf("%d racers won the 0->1 CAS, want exactly 1", won)
		}
		got, _ := r.GetAttestedDeviceByKeyID(ctx, "race-key")
		if got == nil || got.SignCount != 1 {
			t.Fatalf("after race: %#v, want SignCount=1", got)
		}
	})

	t.Run(driver.Name+"/AttestedDeviceStalenessSweep", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		stale, err := r.CreateAttestedDevice(ctx, &service.AttestedDeviceRecord{
			Platform: "ios", KeyID: "stale-key", PublicKeySPKI: "k",
			CreatedAt: 100, LastUsedAt: 1000,
		})
		if err != nil {
			t.Fatalf("create stale: %v", err)
		}
		if _, err := r.CreateAttestedDevice(ctx, &service.AttestedDeviceRecord{
			Platform: "ios", KeyID: "fresh-key", PublicKeySPKI: "k",
			CreatedAt: 100, LastUsedAt: 9000,
		}); err != nil {
			t.Fatalf("create fresh: %v", err)
		}

		if err := r.DeleteStaleAttestedDevices(ctx, 5000, 100); err != nil {
			if errors.Is(err, service.ErrSweepNotImplemented) {
				t.Skip("sweep not implemented for this backend")
			}
			t.Fatalf("sweep: %v", err)
		}

		// Staleness keys on LastUsedAt, not CreatedAt: a long-lived device
		// that refreshed recently must survive.
		if got, _ := r.GetAttestedDeviceByKeyID(ctx, "stale-key"); got != nil {
			t.Errorf("stale device %s survived the sweep", stale)
		}
		if got, _ := r.GetAttestedDeviceByKeyID(ctx, "fresh-key"); got == nil {
			t.Error("recently-used device was swept")
		}

		// A non-positive limit is rejected rather than running unbounded.
		if err := r.DeleteStaleAttestedDevices(ctx, 5000, 0); err == nil {
			t.Error("limit <= 0 must be rejected")
		}
	})

	t.Run(driver.Name+"/AssuranceChallengeSingleUse", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		got, err := r.ConsumeAssuranceChallenge(ctx, "no-such-challenge")
		if err != nil || got != nil {
			t.Fatalf("consume absent = (%#v, %v), want (nil, nil)", got, err)
		}

		c := &service.AssuranceChallengeRecord{
			Challenge: "bm9uY2U", Platform: "ios", ExpiresAt: 9000, CreatedAt: 1000,
		}
		id, err := r.CreateAssuranceChallenge(ctx, c)
		if err != nil || id == "" {
			t.Fatalf("CreateAssuranceChallenge = (%q, %v)", id, err)
		}

		first, err := r.ConsumeAssuranceChallenge(ctx, id)
		if err != nil || first == nil {
			t.Fatalf("first consume = (%#v, %v)", first, err)
		}
		if first.Challenge != "bm9uY2U" || first.Platform != "ios" ||
			first.ExpiresAt != 9000 || first.CreatedAt != 1000 {
			t.Fatalf("consume round-trip mismatch: %#v", first)
		}

		second, err := r.ConsumeAssuranceChallenge(ctx, id)
		if err != nil || second != nil {
			t.Fatalf("second consume = (%#v, %v), want (nil, nil) — challenge redeemed twice", second, err)
		}
	})

	t.Run(driver.Name+"/AssuranceChallengeConcurrentConsume", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		id, err := r.CreateAssuranceChallenge(ctx, &service.AssuranceChallengeRecord{
			Challenge: "cmFjZQ", ExpiresAt: 9000, CreatedAt: 1000,
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}

		const racers = 8
		var wg sync.WaitGroup
		wins := make(chan struct{}, racers)
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := r.ConsumeAssuranceChallenge(ctx, id)
				if err != nil {
					t.Errorf("concurrent consume error: %v", err)
					return
				}
				if got != nil {
					wins <- struct{}{}
				}
			}()
		}
		wg.Wait()
		close(wins)
		won := 0
		for range wins {
			won++
		}
		if won != 1 {
			t.Fatalf("%d racers consumed the challenge, want exactly 1", won)
		}
	})

	t.Run(driver.Name+"/AssuranceChallengeExpirySweep", func(t *testing.T) {
		ctx := context.Background()
		r := driver.NewRepo(t)

		expired, err := r.CreateAssuranceChallenge(ctx, &service.AssuranceChallengeRecord{
			Challenge: "b2xk", ExpiresAt: 1000, CreatedAt: 500,
		})
		if err != nil {
			t.Fatalf("create expired: %v", err)
		}
		live, err := r.CreateAssuranceChallenge(ctx, &service.AssuranceChallengeRecord{
			Challenge: "bmV3", ExpiresAt: 9000, CreatedAt: 500,
		})
		if err != nil {
			t.Fatalf("create live: %v", err)
		}

		if err := r.DeleteExpiredAssuranceChallenges(ctx, 5000, 100); err != nil {
			if errors.Is(err, service.ErrSweepNotImplemented) {
				t.Skip("sweep not implemented for this backend")
			}
			t.Fatalf("sweep: %v", err)
		}

		if got, _ := r.ConsumeAssuranceChallenge(ctx, expired); got != nil {
			t.Fatalf("expired challenge survived the sweep")
		}
		if got, _ := r.ConsumeAssuranceChallenge(ctx, live); got == nil {
			t.Fatalf("live challenge was swept")
		}
	})
}
