package conformance

import (
	"context"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// adversarialValues are free-text payloads that exercise a backend's
// serialization, escaping, and encoding. A value written to a string
// field must read back byte-for-byte regardless of driver — divergence
// means the backend mangles, truncates, or re-encodes payloads.
var adversarialValues = []struct {
	name  string
	value string
}{
	{"unicode_and_emoji", "Zoë Müller 日本語 café 🔐🛂"},
	{"quotes_backslash_control", "O'Brien \"quoted\" back\\slash\nnewline\ttab"},
	{"sql_injection_shaped", "Robert'); DROP TABLE users;--"},
	{"like_wildcards", "100%_off _every_ thing%"},
	{"json_shaped", `{"k":"v","nested":[1,2,{"x":null}]}`},
	{"leading_trailing_space", "   padded value   "},
	{"long_10k", strings.Repeat("Z", 10_000)},
	{"single_char", "x"},
}

// runRoundTripConformance asserts value fidelity: a value written to a
// string or int64 field reads back exactly, through both the create and
// the update paths, for every driver. This catches payload escaping /
// truncation / re-encoding bugs and integer-width loss that the
// happy-path CRUD subtests (which use short ASCII) never touch.
func runRoundTripConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/RoundTrip", func(t *testing.T) {
		t.Run("User_StringFields_OnCreate", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			for i, tc := range adversarialValues {
				email := fmt.Sprintf("rt-create-%d@example.com", i)
				id, err := r.CreateUser(ctx, &service.User{
					Email:        email,
					Name:         tc.value,
					AvatarURL:    tc.value,
					PasswordHash: tc.value,
					Status:       "active",
					Role:         "member",
				})
				if err != nil {
					t.Fatalf("%s: CreateUser: %v", tc.name, err)
				}
				got, err := r.GetUser(ctx, id)
				if err != nil || got == nil {
					t.Fatalf("%s: GetUser: %v %#v", tc.name, err, got)
				}
				assertEqualField(t, tc.name, "Name", tc.value, got.Name)
				assertEqualField(t, tc.name, "AvatarURL", tc.value, got.AvatarURL)
				assertEqualField(t, tc.name, "PasswordHash", tc.value, got.PasswordHash)
			}
		})

		t.Run("User_StringFields_OnUpdate", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			for i, tc := range adversarialValues {
				email := fmt.Sprintf("rt-update-%d@example.com", i)
				id, err := r.CreateUser(ctx, &service.User{Email: email, Status: "active", Role: "member", Name: "placeholder"})
				if err != nil {
					t.Fatalf("%s: CreateUser: %v", tc.name, err)
				}
				if err := r.UpdateUser(ctx, id, map[string]any{
					"name":          tc.value,
					"avatar_url":    tc.value,
					"password_hash": tc.value,
				}); err != nil {
					t.Fatalf("%s: UpdateUser: %v", tc.name, err)
				}
				got, err := r.GetUser(ctx, id)
				if err != nil || got == nil {
					t.Fatalf("%s: GetUser: %v %#v", tc.name, err, got)
				}
				assertEqualField(t, tc.name, "Name", tc.value, got.Name)
				assertEqualField(t, tc.name, "AvatarURL", tc.value, got.AvatarURL)
				assertEqualField(t, tc.name, "PasswordHash", tc.value, got.PasswordHash)
			}
		})

		// DateOfBirthMs must default to 0 (unknown) when omitted at create
		// and round-trip exactly through both create and update, identically
		// on every driver. This is the persistence half of age-gating; the
		// derived band/minor flags are computed in the service layer, not
		// stored.
		t.Run("User_DateOfBirth", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)

			// Omitted at create → 0 (unknown).
			idDefault := createTestUser(t, r, "rt-dob-default@example.com")
			gotDefault, err := r.GetUser(ctx, idDefault)
			if err != nil || gotDefault == nil {
				t.Fatalf("GetUser(default): %v %#v", err, gotDefault)
			}
			if gotDefault.DateOfBirthMs != 0 {
				t.Errorf("default DateOfBirthMs = %d, want 0", gotDefault.DateOfBirthMs)
			}

			// Set at create → reads back exactly.
			const dobCreate int64 = 1_041_465_600_000 // 2003-01-02 UTC
			idCreate, err := r.CreateUser(ctx, &service.User{
				Email: "rt-dob-create@example.com", Status: "active", Role: "member",
				Name: "dob", DateOfBirthMs: dobCreate,
			})
			if err != nil {
				t.Fatalf("CreateUser(dob): %v", err)
			}
			gotCreate, err := r.GetUser(ctx, idCreate)
			if err != nil || gotCreate == nil {
				t.Fatalf("GetUser(create): %v %#v", err, gotCreate)
			}
			if gotCreate.DateOfBirthMs != dobCreate {
				t.Errorf("create DateOfBirthMs = %d, want %d", gotCreate.DateOfBirthMs, dobCreate)
			}

			// Updated → reads back the new value.
			const dobUpdate int64 = 1_577_836_800_000 // 2020-01-01 UTC
			if err := r.UpdateUser(ctx, idCreate, map[string]any{"date_of_birth_ms": dobUpdate}); err != nil {
				t.Fatalf("UpdateUser(dob): %v", err)
			}
			gotUpdate, err := r.GetUser(ctx, idCreate)
			if err != nil || gotUpdate == nil {
				t.Fatalf("GetUser(update): %v %#v", err, gotUpdate)
			}
			if gotUpdate.DateOfBirthMs != dobUpdate {
				t.Errorf("update DateOfBirthMs = %d, want %d", gotUpdate.DateOfBirthMs, dobUpdate)
			}
		})

		// Int64 fidelity: timestamps and counters must survive the full
		// signed-64-bit range without truncation or float coercion.
		t.Run("Int64_Fidelity", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "rt-int64@example.com")
			cases := []struct {
				name      string
				expiresAt int64
				createdAt int64
			}{
				{"max_int64", math.MaxInt64, 1},
				{"large_realistic_ms", 9_223_372_036_854, 1_700_000_000_000},
				{"near_2_pow_53", 1 << 53, (1 << 53) + 1}, // beyond float64 exact-int range
			}
			for i, c := range cases {
				h := fmt.Sprintf("rt-int64-%d", i)
				// SessionStartedAt is the absolute-timeout anchor; it must
				// survive the full int64 range like the other timestamps, and
				// independently of created_at (it is propagated across
				// rotations rather than re-stamped).
				sessionStart := c.createdAt - 1
				if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
					TokenHash: h, UserID: uid, ExpiresAt: c.expiresAt, CreatedAt: c.createdAt, LastUsedAt: c.createdAt,
					SessionStartedAt: sessionStart,
				}); err != nil {
					t.Fatalf("%s: CreateRefreshToken: %v", c.name, err)
				}
				got, err := r.FindRefreshTokenByHash(ctx, h)
				if err != nil || got == nil {
					t.Fatalf("%s: Find: %v %#v", c.name, err, got)
				}
				if got.ExpiresAt != c.expiresAt {
					t.Errorf("%s: ExpiresAt round-trip = %d, want %d", c.name, got.ExpiresAt, c.expiresAt)
				}
				if got.CreatedAt != c.createdAt {
					t.Errorf("%s: CreatedAt round-trip = %d, want %d", c.name, got.CreatedAt, c.createdAt)
				}
				if got.SessionStartedAt != sessionStart {
					t.Errorf("%s: SessionStartedAt round-trip = %d, want %d", c.name, got.SessionStartedAt, sessionStart)
				}
			}
		})

		// Large payloads must round-trip without truncation or
		// corruption, up to a size comfortably under the gRPC message
		// limit. A backend that caps or chunks a single field silently
		// loses data.
		t.Run("LargePayload", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			for _, size := range []int{64 * 1024, 512 * 1024} {
				val := strings.Repeat("x", size)
				id, err := r.CreateUser(ctx, &service.User{
					Email: fmt.Sprintf("rt-large-%d@example.com", size), Name: val,
					Status: "active", Role: "member",
				})
				if err != nil {
					t.Fatalf("size %d: CreateUser: %v", size, err)
				}
				got, err := r.GetUser(ctx, id)
				if err != nil || got == nil {
					t.Fatalf("size %d: GetUser: %v", size, err)
				}
				if len(got.Name) != size {
					t.Errorf("large payload truncated: wrote %d bytes, read back %d", size, len(got.Name))
				} else if got.Name != val {
					t.Errorf("large payload corrupted at size %d (lengths match)", size)
				}
			}
		})
	})
}

func assertEqualField(t *testing.T, caseName, field, want, got string) {
	t.Helper()
	if got != want {
		// Bound the echo so a 10k-char mismatch doesn't flood the log.
		t.Errorf("%s: %s round-trip mismatch:\n  want(len=%d) %.120q\n  got (len=%d) %.120q",
			caseName, field, len(want), want, len(got), got)
	}
}
