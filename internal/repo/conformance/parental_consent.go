package conformance

import (
	"context"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// runParentalConsentConformance pins the cross-driver semantics of the
// parental-consent record methods (CreateParentalConsent /
// GetActiveParentalConsentForChild / MarkParentalConsentRevoked): every driver
// must agree on what "active" means (not revoked), which record wins when a
// child has several (max GrantedAt), that a revoke hides the record from the
// active lookup, and — critically for the audit posture — that a consent record
// survives DeleteUser of the child it references.
func runParentalConsentConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/ParentalConsent", func(t *testing.T) {
		t.Run("CreateGetRevoke_RoundTrip", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			child := createTestUser(t, r, "pc-child@example.com")
			adult := createTestUser(t, r, "pc-adult@example.com")

			if got, err := r.GetActiveParentalConsentForChild(ctx, child); err != nil || got != nil {
				t.Fatalf("GetActive on empty: got %#v err %v, want nil nil", got, err)
			}

			rec := &service.ParentalConsentRecord{
				ConsentID:        "pc-1",
				ChildUserID:      child,
				ConsentingUserID: adult,
				PolicyVersion:    "notice-v1",
				Factors:          "passkey,verified_phone",
				SteppedUp:        true,
				ConsentIP:        "203.0.113.7",
				ConsentUserAgent: "agent/2.0",
				GrantedAt:        1000,
				Market:           "IN",
			}
			if err := r.CreateParentalConsent(ctx, rec); err != nil {
				t.Fatalf("CreateParentalConsent: %v", err)
			}

			got, err := r.GetActiveParentalConsentForChild(ctx, child)
			if err != nil || got == nil {
				t.Fatalf("GetActive: %#v %v", got, err)
			}
			if got.ConsentID != "pc-1" || got.ChildUserID != child || got.ConsentingUserID != adult {
				t.Fatalf("identity mismatch: %#v", got)
			}
			if got.PolicyVersion != "notice-v1" || got.Factors != "passkey,verified_phone" || !got.SteppedUp {
				t.Fatalf("value round-trip mismatch: %#v", got)
			}
			if got.ConsentIP != "203.0.113.7" || got.ConsentUserAgent != "agent/2.0" || got.GrantedAt != 1000 {
				t.Fatalf("value round-trip mismatch: %#v", got)
			}
			// The granted-under market snapshot must round-trip exactly; a
			// record that loses it cannot say which jurisdiction's thresholds
			// it proves consent against.
			if got.Market != "IN" {
				t.Fatalf("market round-trip mismatch: %#v", got)
			}
			if got.RevokedAt != 0 || got.RevokedByUserID != "" {
				t.Fatalf("fresh record must be un-revoked: %#v", got)
			}

			if err := r.MarkParentalConsentRevoked(ctx, "pc-1", adult, 2000); err != nil {
				t.Fatalf("MarkParentalConsentRevoked: %v", err)
			}
			// A revoked record is no longer "active".
			if got, err := r.GetActiveParentalConsentForChild(ctx, child); err != nil || got != nil {
				t.Fatalf("GetActive after revoke: got %#v err %v, want nil nil", got, err)
			}
		})

		t.Run("GetActive_ReturnsMaxGrantedAt_IgnoringRevoked", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			child := createTestUser(t, r, "pc-multi-child@example.com")
			adult := createTestUser(t, r, "pc-multi-adult@example.com")

			// An older, already-revoked consent, then two active ones inserted
			// out of timestamp order.
			seed := []*service.ParentalConsentRecord{
				{ConsentID: "pc-old-revoked", ChildUserID: child, ConsentingUserID: adult, GrantedAt: 100, RevokedAt: 150},
				{ConsentID: "pc-high", ChildUserID: child, ConsentingUserID: adult, GrantedAt: 900},
				{ConsentID: "pc-low", ChildUserID: child, ConsentingUserID: adult, GrantedAt: 300},
			}
			for _, rec := range seed {
				if err := r.CreateParentalConsent(ctx, rec); err != nil {
					t.Fatalf("seed %s: %v", rec.ConsentID, err)
				}
			}
			got, err := r.GetActiveParentalConsentForChild(ctx, child)
			if err != nil || got == nil {
				t.Fatalf("GetActive: %#v %v", got, err)
			}
			if got.ConsentID != "pc-high" {
				t.Fatalf("GetActive = %q, want pc-high (max GrantedAt among non-revoked)", got.ConsentID)
			}
		})

		t.Run("ListActive_ReturnsEveryNonRevoked_NewestFirst", func(t *testing.T) {
			// RevokeParentalConsent's last-guardian rule asks "does another
			// guardian still consent?" about a record it has NOT yet marked
			// revoked, so it needs every active record, not just the latest.
			ctx := context.Background()
			r := driver.NewRepo(t)
			child := createTestUser(t, r, "pc-list-child@example.com")
			a1 := createTestUser(t, r, "pc-list-a1@example.com")
			a2 := createTestUser(t, r, "pc-list-a2@example.com")

			seed := []*service.ParentalConsentRecord{
				{ConsentID: "pcl-revoked", ChildUserID: child, ConsentingUserID: a1, GrantedAt: 100, RevokedAt: 150},
				{ConsentID: "pcl-older", ChildUserID: child, ConsentingUserID: a2, GrantedAt: 300},
				{ConsentID: "pcl-newer", ChildUserID: child, ConsentingUserID: a1, GrantedAt: 900},
			}
			for _, rec := range seed {
				if err := r.CreateParentalConsent(ctx, rec); err != nil {
					t.Fatalf("seed %s: %v", rec.ConsentID, err)
				}
			}

			got, err := r.ListActiveParentalConsentsForChild(ctx, child)
			if err != nil {
				t.Fatalf("ListActive: %v", err)
			}
			if len(got) != 2 || got[0].ConsentID != "pcl-newer" || got[1].ConsentID != "pcl-older" {
				ids := make([]string, 0, len(got))
				for _, rec := range got {
					ids = append(ids, rec.ConsentID)
				}
				t.Fatalf("ListActive = %v, want [pcl-newer pcl-older] (revoked excluded, newest first)", ids)
			}

			// A child with nothing on file gets an empty result, not an error.
			none, err := r.ListActiveParentalConsentsForChild(ctx, "no-such-child")
			if err != nil || len(none) != 0 {
				t.Fatalf("ListActive(unknown child) = %#v %v, want empty and nil", none, err)
			}
		})

		t.Run("SurvivesChildDeletion", func(t *testing.T) {
			// The consent artifact is an audit/compliance record: it must
			// outlive deletion of the child it references, exactly like
			// audit_events, so a regulator can still inspect it after the
			// account is purged.
			ctx := context.Background()
			r := driver.NewRepo(t)
			child := createTestUser(t, r, "pc-del-child@example.com")
			adult := createTestUser(t, r, "pc-del-adult@example.com")
			if err := r.CreateParentalConsent(ctx, &service.ParentalConsentRecord{
				ConsentID: "pc-keep", ChildUserID: child, ConsentingUserID: adult,
				PolicyVersion: "notice-v1", Factors: "verified_phone", SteppedUp: true, GrantedAt: 500,
			}); err != nil {
				t.Fatalf("CreateParentalConsent: %v", err)
			}
			if err := r.DeleteUser(ctx, child); err != nil {
				t.Fatalf("DeleteUser: %v", err)
			}
			got, err := r.GetActiveParentalConsentForChild(ctx, child)
			if err != nil {
				t.Fatalf("GetActive after child delete: %v", err)
			}
			if got == nil || got.ConsentID != "pc-keep" {
				t.Fatalf("consent record must survive child deletion, got %#v", got)
			}
		})
	})
}
